// SPDX-License-Identifier: BSD-3-Clause
//
//! NonceBalance serialization — mirrors derohe `balance_serdes.go`.
//!
//! Wire format: uvarint(NonceHeight) ‖ ElGamal(66 bytes: 33-byte compressed
//! Left + 33-byte compressed Right). The varint is Go's binary.PutUvarint /
//! binary.Uvarint (standard LEB128, little-endian 7-bit groups).

use crate::elgamal::ElGamal;

/// Go `binary.PutUvarint`: LEB128 unsigned varint, least-significant 7-bit
/// group first, high bit set on every group except the last.
pub fn uvarint_encode(mut v: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
    out
}

/// Go `binary.Uvarint`: returns (value, bytes consumed), or None when the
/// buffer is too small (Go: (0, 0)) or the encoding overflows 64 bits
/// (Go: negative size) — both are treated as errors by NonceBalance.
/// Replicates Go's exact rules, including the 10th-byte `b > 1` overflow
/// check (a 10th byte of 0x7f IS rejected by Go even though its low bit
/// would fit, so we must reject it too).
pub fn uvarint_decode(buf: &[u8]) -> Option<(u64, usize)> {
    const MAX_VARINT_LEN: usize = 10;
    let mut x: u64 = 0;
    let mut s: u32 = 0;
    for (i, &b) in buf.iter().enumerate() {
        if i == MAX_VARINT_LEN {
            // caught a read past MaxVarintLen64
            return None;
        }
        if b < 0x80 {
            if i == MAX_VARINT_LEN - 1 && b > 1 {
                return None; // overflow
            }
            return Some((x | u64::from(b) << s, i + 1));
        }
        x |= u64::from(b & 0x7f) << s;
        s += 7;
    }
    // ran off the end of the buffer
    None
}

/// On-chain balance entry: the nonce height of the last update plus the
/// homomorphic ElGamal balance (derohe `NonceBalance`).
#[derive(Debug, Clone, PartialEq)]
pub struct NonceBalance {
    pub nonce_height: u64,
    pub balance: ElGamal,
}

impl NonceBalance {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = uvarint_encode(self.nonce_height);
        out.extend_from_slice(&self.balance.serialize());
        out
    }

    /// Mirrors Go `Unmarshal`: any malformed input is an error (Go panics).
    pub fn deserialize(buf: &[u8]) -> Result<Self, String> {
        let (nonce_height, size) =
            uvarint_decode(buf).ok_or("buf too small or value larger than 64 bits")?;
        if size <= 0 {
            return Err("buf too small or value larger than 64 bits".into());
        }
        let balance = ElGamal::deserialize(&buf[size..])?;
        Ok(NonceBalance { nonce_height, balance })
    }

    /// Mirrors Go `UnmarshalNonce`: read only the leading varint (used to
    /// skip re-decoding balances during verification).
    pub fn parse_nonce(buf: &[u8]) -> Result<u64, String> {
        let (nh, size) =
            uvarint_decode(buf).ok_or("buf too small or value larger than 64 bits")?;
        if size <= 0 {
            return Err("buf too small or value larger than 64 bits".into());
        }
        Ok(nh)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eg(v: u64, r: u64) -> ElGamal {
        use crate::hash_to_point::base_g;
        use ark_ec::PrimeGroup;
        use ark_ff::PrimeField;
        let g = base_g();
        let val = g.mul_bigint(ark_bn254::Fr::from(v).into_bigint());
        let blind = g.mul_bigint(ark_bn254::Fr::from(r).into_bigint());
        ElGamal::new(val, blind)
    }

    #[test]
    fn varint_known_vectors() {
        // Go binary.PutUvarint golden values
        assert_eq!(uvarint_encode(0), vec![0x00]);
        assert_eq!(uvarint_encode(1), vec![0x01]);
        assert_eq!(uvarint_encode(127), vec![0x7f]);
        assert_eq!(uvarint_encode(128), vec![0x80, 0x01]);
        assert_eq!(uvarint_encode(300), vec![0xac, 0x02]);
        assert_eq!(uvarint_encode(624485), vec![0xe5, 0x8e, 0x26]);
        assert_eq!(uvarint_encode(u64::MAX), [vec![0xff; 9], vec![0x01]].concat());
        // roundtrips
        for v in [0u64, 1, 127, 128, 300, 16384, u32::MAX as u64, u64::MAX] {
            let enc = uvarint_encode(v);
            let (dec, n) = uvarint_decode(&enc).unwrap();
            assert_eq!((dec, n), (v, enc.len()));
        }
        // truncated + overflow
        assert!(uvarint_decode(&[0x80]).is_none());
        assert!(uvarint_decode(&[0xff; 10]).is_none());
        assert!(uvarint_decode(&[]).is_none());
        // Go's 10th-byte > 1 overflow rule
        assert!(uvarint_decode(&[vec![0xff; 9], vec![0x7f]].concat()).is_none());
        assert!(uvarint_decode(&[vec![0x80; 9], vec![0x02]].concat()).is_none());
        // 10th byte of 0 or 1 is legal
        assert_eq!(uvarint_decode(&[vec![0xff; 9], vec![0x01]].concat()), Some((u64::MAX, 10)));
        assert_eq!(uvarint_decode(&[vec![0xff; 9], vec![0x00]].concat()), Some((0x7fff_ffff_ffff_ffff, 10)));
    }

    #[test]
    fn nonce_balance_roundtrip() {
        let nb = NonceBalance { nonce_height: 1234567, balance: eg(42, 7) };
        let bytes = nb.serialize();
        // 1-3 byte varint + 66 byte balance
        assert_eq!(bytes.len(), uvarint_encode(1234567).len() + 66);
        let back = NonceBalance::deserialize(&bytes).unwrap();
        assert_eq!(back, nb);
        assert_eq!(NonceBalance::parse_nonce(&bytes).unwrap(), 1234567);
    }

    #[test]
    fn nonce_balance_rejects_truncated() {
        let nb = NonceBalance { nonce_height: 5, balance: eg(1, 1) };
        let bytes = nb.serialize();
        assert!(NonceBalance::deserialize(&bytes[..bytes.len() - 1]).is_err());
        assert!(NonceBalance::deserialize(&bytes[..1]).is_err());
        assert!(NonceBalance::deserialize(&[]).is_err());
    }
}
