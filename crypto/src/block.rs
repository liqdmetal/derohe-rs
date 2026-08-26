// SPDX-License-Identifier: BSD-3-Clause
//
//! Block serialization and hashing — mirrors derohe `block/block.go` and
//! `block/miniblock.go`.
//!
//! Block wire format:
//!   major uvarint ‖ minor uvarint ‖ timestamp(8 BE) ‖ height uvarint ‖
//!   miner_tx (full transaction serialize) ‖ proof(32) ‖
//!   tips_count uvarint + tips(32 each) ‖
//!   miniblocks_count uvarint (0x00 when empty) + miniblocks(48 each) ‖
//!   tx_hashes_count uvarint + tx_hashes(32 each)
//!
//! CRITICAL: the block hash uses **NIST SHA3-256** (golang.org/x/crypto/sha3
//! Sum256), NOT the legacy Keccak-256 used for transaction hashes.

use crate::balance_serdes::{uvarint_decode, uvarint_encode};
use crate::transaction::Transaction;
use tiny_keccak::{Hasher, Sha3};

pub const MINIBLOCK_SIZE: usize = 48;

/// NIST SHA3-256 (golang.org/x/crypto/sha3 Sum256).
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha3::v256();
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    out
}

#[derive(Debug, Clone)]
pub struct MiniBlock {
    pub version: u8,
    pub high_diff: bool,
    pub final_block: bool,
    pub past_count: u8,
    pub timestamp: u16,
    pub height: u64,
    pub past: [u32; 2],
    pub key_hash: [u8; 32], // only the first 16 bytes are serialized
    pub flags: u32,
    pub nonce: [u32; 3],
}

impl MiniBlock {
    fn sanity(&self) -> Result<(), String> {
        if self.version >= 16 {
            return Err("version not supported".into());
        }
        if self.past_count > 2 {
            return Err("tips cannot be more than 2".into());
        }
        if self.past_count == 0 {
            return Err("miniblock must have tips".into());
        }
        if self.height >= 0xffffffffff {
            return Err("miniblock height not possible".into());
        }
        if self.past_count == 2 && self.past[0] == self.past[1] {
            return Err("tips cannot collide".into());
        }
        Ok(())
    }

    /// Go `MiniBlock.Serialize` (48 bytes). Panics on sanity failure, like Go.
    pub fn serialize(&self) -> Vec<u8> {
        self.sanity().expect("miniblock sanity");
        let mut versionbyte = (self.version & 0x0f) | ((self.past_count & 0x03) << 6);
        if self.high_diff {
            versionbyte |= 0x10;
        }
        if self.final_block {
            versionbyte |= 0x20;
        }
        let mut out = Vec::with_capacity(MINIBLOCK_SIZE);
        out.push(versionbyte);
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        let hb = self.height.to_be_bytes();
        out.extend_from_slice(&hb[3..8]); // 5 bytes
        for p in &self.past {
            out.extend_from_slice(&p.to_be_bytes());
        }
        out.extend_from_slice(&self.key_hash[..16]);
        out.extend_from_slice(&self.flags.to_be_bytes());
        for n in &self.nonce {
            out.extend_from_slice(&n.to_be_bytes());
        }
        assert_eq!(out.len(), MINIBLOCK_SIZE);
        out
    }

    /// Go `MiniBlock.Deserialize` (exactly 48 bytes consumed).
    pub fn deserialize(buf: &[u8]) -> Result<MiniBlock, String> {
        if buf.len() < MINIBLOCK_SIZE {
            return Err(format!(
                "Expected {} bytes. Actual {}",
                MINIBLOCK_SIZE,
                buf.len()
            ));
        }
        let version = buf[0] & 0x0f;
        if version != 1 {
            return Err(format!("unknown version '{}'", version));
        }
        let past_count = buf[0] >> 6;
        let high_diff = buf[0] & 0x10 > 0;
        let final_block = buf[0] & 0x20 > 0;
        let timestamp = u16::from_be_bytes([buf[1], buf[2]]);
        let mut hb = [0u8; 8];
        hb[3..8].copy_from_slice(&buf[3..8]);
        let height = u64::from_be_bytes(hb);
        let mut past = [0u32; 2];
        past[0] = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        past[1] = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let mut key_hash = [0u8; 32];
        key_hash[..16].copy_from_slice(&buf[16..32]);
        let flags = u32::from_be_bytes([buf[32], buf[33], buf[34], buf[35]]);
        let nonce = [
            u32::from_be_bytes([buf[36], buf[37], buf[38], buf[39]]),
            u32::from_be_bytes([buf[40], buf[41], buf[42], buf[43]]),
            u32::from_be_bytes([buf[44], buf[45], buf[46], buf[47]]),
        ];
        let mbl = MiniBlock {
            version,
            high_diff,
            final_block,
            past_count,
            timestamp,
            height,
            past,
            key_hash,
            flags,
            nonce,
        };
        mbl.sanity()?;
        Ok(mbl)
    }
}

#[derive(Debug, Clone)]
pub struct Block {
    pub major_version: u64,
    pub minor_version: u64,
    pub timestamp: u64,
    pub height: u64,
    pub miner_tx: Transaction,
    pub proof: [u8; 32],
    pub tips: Vec<[u8; 32]>,
    pub mini_blocks: Vec<MiniBlock>,
    pub tx_hashes: Vec<[u8; 32]>,
}

impl Block {
    /// Go `Block.serialize(skiplastminiblock)`.
    pub fn serialize(&self, skip_last_mini_block: bool) -> Vec<u8> {
        let mut out = uvarint_encode(self.major_version);
        out.extend_from_slice(&uvarint_encode(self.minor_version));
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&uvarint_encode(self.height));
        out.extend_from_slice(&self.miner_tx.serialize(3));
        out.extend_from_slice(&self.proof);
        out.extend_from_slice(&uvarint_encode(self.tips.len() as u64));
        for t in &self.tips {
            out.extend_from_slice(t);
        }
        if self.mini_blocks.is_empty() {
            out.push(0);
        } else if !skip_last_mini_block {
            out.extend_from_slice(&uvarint_encode(self.mini_blocks.len() as u64));
            for m in &self.mini_blocks {
                out.extend_from_slice(&m.serialize());
            }
        } else {
            let length = self.mini_blocks.len() - 1;
            out.extend_from_slice(&uvarint_encode(length as u64));
            for m in self.mini_blocks.iter().take(length) {
                out.extend_from_slice(&m.serialize());
            }
        }
        out.extend_from_slice(&uvarint_encode(self.tx_hashes.len() as u64));
        for t in &self.tx_hashes {
            out.extend_from_slice(t);
        }
        out
    }

    /// Go `Block.GetHash`: NIST SHA3-256 of the full serialization.
    pub fn get_hash(&self) -> [u8; 32] {
        sha3_256(&self.serialize(false))
    }

    /// Go `Block.GetHashSkipLastMiniBlock`.
    pub fn get_hash_skip_last_mini_block(&self) -> [u8; 32] {
        sha3_256(&self.serialize(true))
    }

    /// Go `Block.GetTipsHash`: SHA3-256 of the concatenated tips.
    pub fn get_tips_hash(&self) -> [u8; 32] {
        let mut data = Vec::with_capacity(self.tips.len() * 32);
        for t in &self.tips {
            data.extend_from_slice(t);
        }
        sha3_256(&data)
    }

    /// Go `Block.GetTXSHash`: SHA3-256 of the concatenated tx hashes.
    pub fn get_txs_hash(&self) -> [u8; 32] {
        let mut data = Vec::with_capacity(self.tx_hashes.len() * 32);
        for t in &self.tx_hashes {
            data.extend_from_slice(t);
        }
        sha3_256(&data)
    }

    /// Go `Block.Deserialize`. NOTE: unlike the tx parser, Go's block
    /// Deserialize does NOT reject trailing bytes.
    pub fn deserialize(buf: &[u8]) -> Result<Block, String> {
        let mut pos = 0usize;
        let mut take_var = |buf: &[u8], pos: &mut usize| -> Result<u64, String> {
            let (v, n) = uvarint_decode(&buf[*pos..]).ok_or("bad varint")?;
            if n <= 0 {
                return Err("bad varint".into());
            }
            *pos += n;
            Ok(v)
        };

        let major_version = take_var(buf, &mut pos)?;
        let minor_version = take_var(buf, &mut pos)?;
        if buf.len() - pos < 8 {
            return Err("Incomplete timestamp in Block".into());
        }
        let timestamp = u64::from_be_bytes(buf[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let height = take_var(buf, &mut pos)?;

        let miner_tx = Transaction::deserialize(&buf[pos..], 3)?;
        let used = miner_tx.serialize(3).len();
        pos += used;
        if buf.len() - pos < 32 {
            return Err("block: missing proof".into());
        }
        let mut proof = [0u8; 32];
        proof.copy_from_slice(&buf[pos..pos + 32]);
        pos += 32;

        let tips_count = take_var(buf, &mut pos)?;
        if tips_count as usize > buf.len().saturating_sub(pos) / 32 {
            return Err("block: tips overflow".into());
        }
        let mut tips = Vec::with_capacity(tips_count as usize);
        for _ in 0..tips_count {
            tips.push(buf[pos..pos + 32].try_into().unwrap());
            pos += 32;
        }

        let mbl_count = take_var(buf, &mut pos)?;
        let mut mini_blocks = Vec::with_capacity(mbl_count as usize);
        for _ in 0..mbl_count {
            let m = MiniBlock::deserialize(&buf[pos..])?;
            pos += MINIBLOCK_SIZE;
            mini_blocks.push(m);
        }

        let tx_count = take_var(buf, &mut pos)?;
        if tx_count as usize > buf.len().saturating_sub(pos) / 32 {
            return Err("block: tx_hashes overflow".into());
        }
        let mut tx_hashes = Vec::with_capacity(tx_count as usize);
        for _ in 0..tx_count {
            tx_hashes.push(buf[pos..pos + 32].try_into().unwrap());
            pos += 32;
        }

        Ok(Block {
            major_version,
            minor_version,
            timestamp,
            height,
            miner_tx,
            proof,
            tips,
            mini_blocks,
            tx_hashes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mbl(i: u32) -> MiniBlock {
        MiniBlock {
            version: 1,
            high_diff: i % 2 == 0,
            final_block: i % 3 == 0,
            past_count: 1 + (i % 2) as u8,
            timestamp: (i as u16).wrapping_mul(7),
            height: 1000 + u64::from(i),
            past: [i, i + 1],
            key_hash: [i as u8; 32],
            flags: i * 3,
            nonce: [i, i + 1, i + 2],
        }
    }

    #[test]
    fn miniblock_48_bytes_roundtrip() {
        for i in 0..5u32 {
            let m = mbl(i);
            let s = m.serialize();
            assert_eq!(s.len(), MINIBLOCK_SIZE);
            let back = MiniBlock::deserialize(&s).unwrap();
            assert_eq!(back.version, 1);
            assert_eq!(back.height, m.height);
            assert_eq!(back.past, m.past);
            assert_eq!(back.key_hash[..16], m.key_hash[..16]);
            assert_eq!(back.flags, m.flags);
            assert_eq!(back.nonce, m.nonce);
            assert_eq!(back.past_count, m.past_count);
            assert_eq!(back.high_diff, m.high_diff);
            assert_eq!(back.final_block, m.final_block);
            assert_eq!(back.timestamp, m.timestamp);
        }
        assert!(MiniBlock::deserialize(&[0u8; 47]).is_err());
    }

    #[test]
    fn sha3_256_known() {
        // NIST SHA3-256("") — official test vector
        assert_eq!(
            sha3_256(b""),
            hex_lit("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
        );
        // SHA3-256("abc")
        assert_eq!(
            sha3_256(b"abc"),
            hex_lit("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
        );
    }

    fn hex_lit(s: &str) -> [u8; 32] {
        let b = hex::decode(s).unwrap();
        b.try_into().unwrap()
    }

    #[test]
    fn block_roundtrip() {
        // minimal premine block with 1 tip, 2 miniblocks, 2 tx hashes
        let tx = crate::transaction::Transaction {
            version: 1,
            source_network: 0,
            dest_network: 0,
            tx_type: crate::transaction::TX_COINBASE,
            value: 0,
            miner_address: [7u8; 33],
            c: [0u8; 32],
            s: [0u8; 32],
            height: 0,
            blid: [0u8; 32],
            scdata: crate::rpc_args::Arguments::default(),
            payloads: Vec::new(),
        };
        let bl = Block {
            major_version: 9,
            minor_version: 0,
            timestamp: 1700000000000,
            height: 12345,
            miner_tx: tx,
            proof: [1u8; 32],
            tips: vec![[2u8; 32]],
            mini_blocks: vec![mbl(1), mbl(2)],
            tx_hashes: vec![[3u8; 32], [4u8; 32]],
        };
        let s = bl.serialize(false);
        let back = Block::deserialize(&s).unwrap();
        assert_eq!(back.serialize(false), s);
        assert_eq!(back.serialize(true), bl.serialize(true));
        assert_eq!(back.get_hash(), bl.get_hash());
        assert_eq!(back.get_tips_hash(), bl.get_tips_hash());
        assert_eq!(back.get_txs_hash(), bl.get_txs_hash());
        // skip-last differs from full
        assert_ne!(bl.serialize(true), bl.serialize(false));
        // truncated fails
        assert!(Block::deserialize(&s[..s.len() - 40]).is_err());
    }
}
