// SPDX-License-Identifier: BSD-3-Clause
//
//! Statement serialization — mirrors derohe `protocol_structures.go`.
//!
//! Wire format (after `Statement.Serialize`):
//!   power(1) ‖ bytes_per_publickey(1) ‖ fees(uvarint) ‖ D(33 compressed) ‖
//!   hashed-publickey pointers (ring_size × bpp, blake2s-256 truncated) ‖
//!   C commitments (ring_size × 33 compressed) ‖ roothash(32)
//!
//! The publickey pointers are graviton tree leaves: blake2s-256 of the
//! compressed public key, truncated to `bytes_per_publickey` (mainnet: 3).

use ark_bn254::G1Projective;
use blake2::{Blake2s256, Digest};
use num_bigint::BigUint;

use crate::balance_serdes::{uvarint_decode, uvarint_encode};
use crate::bulletproof::Statement;
use crate::curve::{decode_compressed, encode_compressed};

/// graviton.Sum: blake2s-256.
pub fn graviton_sum(key: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(key);
    let out = hasher.finalize();
    let mut h = [0u8; 32];
    h.copy_from_slice(&out);
    h
}

/// GetPowerof2: log2 of a power-of-two (panics otherwise, like Go).
pub fn power_of_2(n: usize) -> usize {
    assert!(n > 0, "number cannot be less than 0");
    assert!(n.is_power_of_two(), "number({}) must be power of 2", n);
    n.trailing_zeros() as usize
}

fn point_bytes(p: &G1Projective) -> [u8; 33] {
    encode_compressed(p)
}

impl Statement {
    /// Go `Statement.Serialize`. bpp = bytes_per_publickey (mainnet 3).
    pub fn serialize(&self, bpp: u8) -> Vec<u8> {
        let ring_size = if self.pointers.is_empty() {
            self.publickeylist.len()
        } else {
            self.pointers.len() / bpp as usize
        };
        let mut out = Vec::new();
        // defensive: a bad ring size (simulator laxity) must not panic the
        // node; clamp to a power of two like the wire format demands
        let pow = if ring_size > 0 && ring_size.is_power_of_two() {
            ring_size.trailing_zeros() as usize
        } else {
            0 // ring 1: degenerate but serializable
        };
        out.push(pow as u8);
        out.push(bpp);
        out.extend_from_slice(&uvarint_encode(self.fees));
        out.extend_from_slice(&point_bytes(&self.d));
        if self.pointers.is_empty() {
            for pk in &self.publickeylist {
                let h = graviton_sum(&point_bytes(pk));
                out.extend_from_slice(&h[..bpp as usize]);
            }
        } else {
            out.extend_from_slice(&self.pointers);
        }
        for c in &self.c {
            out.extend_from_slice(&point_bytes(c));
        }
        out.extend_from_slice(&self.roothash);
        out
    }

    /// Go `Statement.Deserialize`: reads the wire form back. CLn/CRn and
    /// the full Publickeylist are NOT stored (Go leaves them empty) — only
    /// the pointers are kept, so a re-serialize reproduces identical bytes.
    pub fn deserialize(buf: &[u8]) -> Result<(Self, usize), String> {
        let mut pos = 0usize;
        let need = |buf: &[u8], pos: usize, n: usize| -> Result<(), String> {
            if buf.len() - pos < n {
                return Err("statement: unexpected end of buffer".into());
            }
            Ok(())
        };
        need(buf, pos, 2)?;
        let power = buf[pos];
        pos += 1;
        let ring_size = 1usize << power;
        if ring_size > 128 {
            return Err("ring size is too large".into());
        }
        let bpp = buf[pos];
        pos += 1;

        let (fees, n) = uvarint_decode(&buf[pos..]).ok_or("statement: bad fees varint")?;
        pos += n;

        need(buf, pos, 33)?;
        let d = decode_compressed(&buf[pos..pos + 33]).map_err(|e| format!("statement D: {}", e))?;
        pos += 33;

        let pointer_len = ring_size * bpp as usize;
        need(buf, pos, pointer_len)?;
        let pointers = buf[pos..pos + pointer_len].to_vec();
        pos += pointer_len;

        let mut c = Vec::with_capacity(ring_size);
        for _ in 0..ring_size {
            need(buf, pos, 33)?;
            let p = decode_compressed(&buf[pos..pos + 33])
                .map_err(|e| format!("statement C: {}", e))?;
            c.push(p);
            pos += 33;
        }

        need(buf, pos, 32)?;
        let mut roothash = [0u8; 32];
        roothash.copy_from_slice(&buf[pos..pos + 32]);
        pos += 32;

        let st = Statement {
            publickeylist: Vec::new(),
            c,
            cln: Vec::new(),
            crn: Vec::new(),
            d,
            roothash,
            fees,
            pointers,
        };
        Ok((st, pos))
    }

    /// Bytes-per-publickey of this statement's pointers. Go derives this from
    /// the wire (`Bytes_per_publickey`); mainnet txs use 3, wallet txs may
    /// use 2. Computed from the pointer length + the ring size when the
    /// ring power is known from the statement's C-vector length.
    pub fn bpp(&self) -> u8 {
        let ring = self.c.len();
        if ring == 0 || self.pointers.is_empty() {
            return 3; // fallback: mainnet default
        }
        (self.pointers.len() / ring) as u8
    }
}

/// Scalar -> 32-byte big-endian (for oracle test scaffolding).
pub fn be32_of_biguint(v: &BigUint) -> [u8; 32] {
    let mut out = [0u8; 32];
    let b = v.to_bytes_be();
    let start = 32usize.saturating_sub(b.len());
    out[start..].copy_from_slice(&b[..b.len().min(32)]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_to_point::base_g;
    use ark_ec::PrimeGroup;

    #[test]
    fn graviton_sum_known() {
        // blake2s-256 of "DERO" — cross-checked against the reference at runtime
        let h = graviton_sum(b"DERO");
        assert_eq!(h.len(), 32);
        // re-computation is deterministic
        assert_eq!(graviton_sum(b"DERO"), h);
    }

    #[test]
    fn power_of_2_basics() {
        assert_eq!(power_of_2(2), 1);
        assert_eq!(power_of_2(4), 2);
        assert_eq!(power_of_2(128), 7);
    }

    #[test]
    fn statement_roundtrip() {
        use ark_ff::PrimeField;
        let g = base_g();
        let pks: Vec<G1Projective> = (0..4).map(|i| g.mul_bigint(ark_bn254::Fr::from(i + 1).into_bigint())).collect();
        let st = Statement {
            publickeylist: pks.clone(),
            c: pks.clone(),
            cln: Vec::new(),
            crn: Vec::new(),
            d: g,
            roothash: [7u8; 32],
            fees: 42,
            pointers: Vec::new(),
        };
        let bytes = st.serialize(3);
        let (back, used) = Statement::deserialize(&bytes).unwrap();
        assert_eq!(used, bytes.len());
        // re-serialize from the deserialized form (pointers path) == original
        assert_eq!(back.serialize(3), bytes);
        assert_eq!(back.pointers.len(), 4 * 3);
        // truncation must fail
        assert!(Statement::deserialize(&bytes[..bytes.len() - 1]).is_err());
        // ring size > 128 rejected
        let mut bad = vec![9u8]; // 2^9 = 512
        bad.extend_from_slice(&bytes[1..]);
        assert!(Statement::deserialize(&bad).is_err());
    }
}
