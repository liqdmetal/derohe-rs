//! Account-model ElGamal encryption, mirroring derohe
//! `cryptography/crypto/algebra_elgamal.go`.
//!
//! Ciphertext is a pair of G1 points:
//!   Left  = value*G + r*key
//!   Right = r*G
//! with G = HashToPoint(keccak256("DEROG")) (NOT the standard generator).
//! Serialized form is 66 bytes = left(33) || right(33), DERO-compressed.

use ark_bn254::{G1Affine, G1Projective};
use ark_ec::PrimeGroup;

use crate::curve::{be32_to_bigint, decode_compressed, encode_compressed};
use crate::hash_to_point::base_g;

#[derive(Clone, Debug, PartialEq)]
pub struct ElGamal {
    pub left: G1Projective,
    pub right: G1Projective,
}

impl ElGamal {
    pub fn new(left: G1Projective, right: G1Projective) -> Self {
        Self { left, right }
    }

    /// Deterministic commit with injected randomness (harness injects r so the
    /// two implementations can be compared byte-for-byte):
    ///   left = value*G + r*key, right = r*G
    pub fn commit(key: &G1Projective, value: &[u8; 32], randomness: &[u8; 32]) -> Self {
        let g = base_g();
        let v = be32_to_bigint(value);
        let r = be32_to_bigint(randomness);
        let left = g.mul_bigint(v) + key.mul_bigint(r);
        let right = g.mul_bigint(r);
        Self { left, right }
    }

    pub fn add(&self, other: &ElGamal) -> Self {
        Self {
            left: self.left + other.left,
            right: self.right + other.right,
        }
    }

    pub fn plus(&self, value: &[u8; 32]) -> Self {
        let v = be32_to_bigint(value);
        Self {
            left: self.left + base_g().mul_bigint(v),
            right: self.right,
        }
    }

    pub fn mul(&self, scalar: &[u8; 32]) -> Self {
        let s = be32_to_bigint(scalar);
        Self {
            left: self.left.mul_bigint(s),
            right: self.right.mul_bigint(s),
        }
    }

    pub fn neg(&self) -> Self {
        Self {
            left: -self.left,
            right: -self.right,
        }
    }

    pub fn serialize(&self) -> [u8; 66] {
        let mut out = [0u8; 66];
        out[..33].copy_from_slice(&encode_compressed(&self.left));
        out[33..].copy_from_slice(&encode_compressed(&self.right));
        out
    }

    pub fn deserialize(b: &[u8]) -> Result<Self, String> {
        if b.len() != 66 {
            return Err(format!("insufficient buffer size: {}", b.len()));
        }
        let left = decode_compressed(&b[..33])?;
        let right = decode_compressed(&b[33..])?;
        Ok(Self { left, right })
    }

    /// Decrypt with secret key s: left - s*right = value*G.
    pub fn decrypt(&self, s: &[u8; 32]) -> G1Projective {
        let sb = be32_to_bigint(s);
        self.left - self.right.mul_bigint(sb)
    }
}

/// Convert an affine-friendly hex point (33 bytes) to projective.
pub fn point_from_compressed_hex(h: &str) -> Result<G1Projective, String> {
    let bytes = hex::decode(h).map_err(|e| e.to_string())?;
    decode_compressed(&bytes)
}

pub fn point_to_compressed_hex(p: &G1Projective) -> String {
    hex::encode(encode_compressed(p))
}

pub fn affine(p: &G1Projective) -> G1Affine {
    (*p).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::PrimeGroup;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        // secret key s, public key P = s*G
        let s: [u8; 32] = {
            let mut b = [0u8; 32];
            b[31] = 42;
            b
        };
        let g = base_g();
        let key = g.mul_bigint(be32_to_bigint(&s));

        let value: [u8; 32] = {
            let mut b = [0u8; 32];
            b[30] = 1000u16.to_be_bytes()[0];
            b[31] = 1000u16.to_be_bytes()[1]; // value = 1000
            b
        };
        let r: [u8; 32] = {
            let mut b = [0u8; 32];
            b[31] = 7;
            b
        };

        let c = ElGamal::commit(&key, &value, &r);
        let m = c.decrypt(&s);
        // expect value*G
        let expect = g.mul_bigint(be32_to_bigint(&value));
        assert_eq!(m, expect);
    }

    #[test]
    fn serialize_roundtrip() {
        let s: [u8; 32] = {
            let mut b = [0u8; 32];
            b[31] = 42;
            b
        };
        let key = base_g().mul_bigint(be32_to_bigint(&s));
        let mut value = [0u8; 32];
        value[31] = 100;
        let mut r = [0u8; 32];
        r[31] = 7;
        let c = ElGamal::commit(&key, &value, &r);
        let bytes = c.serialize();
        assert_eq!(bytes.len(), 66);
        let c2 = ElGamal::deserialize(&bytes).unwrap();
        assert_eq!(c, c2);
    }

    #[test]
    #[should_panic]
    fn zero_ciphertext_not_serializable() {
        // Quirk (matches Go reference): identity encodes to 33 zero bytes and
        // x=0 yields a non-residue, so the zero ciphertext cannot roundtrip.
        let s: [u8; 32] = {
            let mut b = [0u8; 32];
            b[31] = 42;
            b
        };
        let key = base_g().mul_bigint(be32_to_bigint(&s));
        let c = ElGamal::commit(&key, &[0u8; 32], &[0u8; 32]);
        let bytes = c.serialize();
        let _ = ElGamal::deserialize(&bytes).unwrap();
    }
}
