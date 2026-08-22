//! alt_bn128 (BN254) group operations and the DERO-specific point codec.
//!
//! Mirrors derohe `cryptography/bn256` + `cryptography/crypto/group.go`.
//! The compressed encoding is DERO-specific (NOT SEC1):
//!   33 bytes = x (32B big-endian) || flag byte
//!   flag 0x00 = the smaller of {y, p-y}, flag 0x01 = the larger.

use ark_bn254::{Fq, G1Affine, G1Projective};
use ark_ec::AffineRepr;
use ark_ff::{BigInt, Field, PrimeField};
use num_bigint::BigUint;

/// alt_bn128 field prime p.
pub const P_HEX: &str = "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";
/// alt_bn128 group order n.
pub const N_HEX: &str = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";

pub fn bigint_from_hex(h: &str) -> BigInt<4> {
    let bytes = hex::decode(h).expect("valid hex");
    assert_eq!(bytes.len(), 32, "must be exactly 32 bytes");
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        limbs[3 - i] = u64::from_be_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
    }
    BigInt::new(limbs)
}

/// 32 big-endian bytes -> ark BigInt<4> (limbs are little-endian u64 words).
pub fn be32_to_bigint(b: &[u8]) -> BigInt<4> {
    assert_eq!(b.len(), 32, "scalar must be exactly 32 bytes");
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        limbs[3 - i] = u64::from_be_bytes(b[i * 8..(i + 1) * 8].try_into().unwrap());
    }
    BigInt::new(limbs)
}

/// ark BigInt<4> -> BigUint (integer value).
pub fn bigint_to_biguint(bi: BigInt<4>) -> BigUint {
    let mut le = Vec::with_capacity(32);
    for limb in bi.0 {
        le.extend_from_slice(&limb.to_le_bytes());
    }
    BigUint::from_bytes_le(&le)
}

/// BigInt<4> -> 32 big-endian bytes (zero-padded).
pub fn bigint_to_be32(bi: BigInt<4>) -> [u8; 32] {
    let bytes = bigint_to_biguint(bi).to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

pub fn p_as_biguint() -> BigUint {
    BigUint::from_bytes_be(&hex::decode(P_HEX).unwrap())
}

/// DERO compressed encoding (33 bytes). Identity encodes as 33 zero bytes,
/// matching the Go reference (64-byte zero Marshal + flag 0x00).
pub fn encode_compressed(p: &G1Projective) -> [u8; 33] {
    let a = G1Affine::from(*p);
    let mut out = [0u8; 33];
    if a.is_zero() {
        return out;
    }
    let x = a.x().unwrap();
    let y = a.y().unwrap();
    out[..32].copy_from_slice(&bigint_to_be32(x.into_bigint()));
    // flag: 0x00 if y < p - y  <=>  2*y < p  (integer comparison)
    let p_bi = p_as_biguint();
    let y_bi = bigint_to_biguint(y.into_bigint());
    out[32] = if &y_bi * 2u32 < p_bi { 0x00 } else { 0x01 };
    out
}

/// DERO uncompressed encoding (64 bytes, x||y big-endian), matching Go Marshal.
pub fn encode_uncompressed(p: &G1Projective) -> [u8; 64] {
    let a = G1Affine::from(*p);
    let mut out = [0u8; 64];
    if a.is_zero() {
        return out;
    }
    let x = a.x().unwrap();
    let y = a.y().unwrap();
    out[..32].copy_from_slice(&bigint_to_be32(x.into_bigint()));
    out[32..].copy_from_slice(&bigint_to_be32(y.into_bigint()));
    out
}

/// Decode a DERO compressed point. x >= p is rejected (the Go reference's
/// behavior for x >= p is undefined; see README "known divergences").
pub fn decode_compressed(b: &[u8]) -> Result<G1Projective, String> {
    if b.len() != 33 {
        return Err(format!("wrong encoded point size: {}", b.len()));
    }
    let flag = b[32];
    if flag > 1 {
        return Err(format!("invalid flag byte: {}", flag));
    }
    let x_bi = be32_to_bigint(&b[..32]);
    let x = Fq::from_bigint(x_bi).ok_or("x >= field prime")?;
    // y = (x^3 + 3)^((p+1)/4); verify y^2 == x^3 + 3
    let rhs = x.square() * x + Fq::from(3u32);
    let exp = bigint_from_hex("0c19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f52");
    let mut y = rhs.pow(&exp);
    if y.square() != rhs {
        return Err("not a square mod P".into());
    }
    // select root by flag: 0x00 = smaller root
    let p_bi = p_as_biguint();
    let y_bi = bigint_to_biguint(y.into_bigint());
    let y_is_smaller = &y_bi * 2u32 < p_bi;
    if (flag == 0x00 && !y_is_smaller) || (flag == 0x01 && y_is_smaller) {
        y = -y;
    }
    Ok(G1Affine::new_unchecked(x, y).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::PrimeGroup;
    use ark_ff::fields::AdditiveGroup;

    #[test]
    fn generator_roundtrip() {
        let g = G1Projective::generator(); // (1, 2) on y^2 = x^3 + 3
        let enc = encode_compressed(&g);
        // x=1, y=2: 2y=4 < p -> flag 0x00
        let mut expect_x = [0u8; 32];
        expect_x[31] = 1;
        assert_eq!(&enc[..32], &expect_x);
        assert_eq!(enc[32], 0x00);
        let dec = decode_compressed(&enc).unwrap();
        assert_eq!(dec, g);
    }

    #[test]
    fn identity_encodes_as_zeros() {
        let z = G1Projective::ZERO;
        assert_eq!(encode_compressed(&z), [0u8; 33]);
    }

    #[test]
    fn neg_toggle_flag() {
        let g = G1Projective::generator();
        let enc_g = encode_compressed(&g);
        let enc_ng = encode_compressed(&(-g));
        assert_eq!(enc_g[..32], enc_ng[..32]);
        assert_eq!(enc_g[32] ^ enc_ng[32], 0x01); // flags must differ
        let dec = decode_compressed(&enc_ng).unwrap();
        assert_eq!(dec, -g);
    }
}
