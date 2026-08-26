// SPDX-License-Identifier: BSD-3-Clause
//
//! FieldVector: vectors of scalars mod n, mirroring derohe
//! `cryptography/crypto/algebra_fieldvector.go` + `fieldvector.go`.
//!
//! Go stores RAW big.Int values (NOT pre-reduced). Non-arithmetic ops
//! (flip/extract/slice/concat/clone) preserve the raw bytes; only arithmetic
//! ops (add/hadamard/times/innerproduct/sum/negate/invert) reduce mod n.
//! Rust mirrors this exactly: elements are stored as raw 32-byte BE values
//! and reduced only inside arithmetic.

use ark_bn254::Fr;
use ark_ff::{Field, PrimeField};
use ark_ff::fields::AdditiveGroup;

use crate::curve::{be32_to_bigint, bigint_to_be32, N_HEX};
use num_bigint::BigUint;

/// Build an Fr from 32 big-endian bytes, reducing mod n.
pub fn fr_from_be_bytes(b: &[u8]) -> Fr {
    assert_eq!(b.len(), 32, "field element must be exactly 32 bytes");
    let n = BigUint::from_bytes_be(&hex::decode(N_HEX).expect("valid n hex"));
    let v = BigUint::from_bytes_be(b) % &n;
    let bytes = v.to_bytes_be();
    let mut xb = [0u8; 32];
    xb[32 - bytes.len()..].copy_from_slice(&bytes);
    Fr::from_bigint(be32_to_bigint(&xb)).expect("reduced value < n")
}

/// Fr -> 32 big-endian bytes.
pub fn fr_to_be_bytes(f: Fr) -> [u8; 32] {
    bigint_to_be32(f.into_bigint())
}

pub fn fr_from_hex(h: &str) -> Fr {
    fr_from_be_bytes(&hex::decode(h).expect("valid hex"))
}

pub fn fr_to_hex(f: Fr) -> String {
    hex::encode(fr_to_be_bytes(f))
}

#[derive(Clone, Debug, PartialEq)]
pub struct FieldVector(pub Vec<[u8; 32]>);

impl FieldVector {
    pub fn new(v: Vec<[u8; 32]>) -> Self {
        Self(v)
    }

    pub fn from_hex(hexes: &[String]) -> Self {
        Self(hexes.iter().map(|h| {
            let b = hex::decode(h).expect("valid hex");
            assert_eq!(b.len(), 32, "field element must be 32 bytes");
            let mut a = [0u8; 32];
            a.copy_from_slice(&b);
            a
        }).collect())
    }

    pub fn to_hex(&self) -> Vec<String> {
        self.0.iter().map(|b| hex::encode(b)).collect()
    }

    pub fn length(&self) -> usize {
        self.0.len()
    }

    pub fn element(&self, i: usize) -> [u8; 32] {
        self.0[i]
    }

    pub fn element_fr(&self, i: usize) -> Fr {
        fr_from_be_bytes(&self.0[i])
    }

    pub fn slice(&self, start: usize, end: usize) -> Self {
        Self(self.0[start..end].to_vec())
    }

    pub fn clone_(&self) -> Self {
        Self(self.0.clone())
    }

    /// Reverse-with-wrap, matching Go's `(len-i) % len` indexing. RAW bytes.
    pub fn flip(&self) -> Self {
        let n = self.0.len();
        Self((0..n).map(|i| self.0[(n - i) % n]).collect())
    }

    /// Sum mod n.
    pub fn sum(&self) -> Fr {
        self.0.iter().fold(Fr::ZERO, |acc, x| acc + fr_from_be_bytes(x))
    }

    pub fn add(&self, other: &Self) -> Self {
        assert_eq!(self.0.len(), other.0.len(), "mismatched number of elements");
        Self(self.0.iter().zip(&other.0).map(|(a, b)| fr_to_be_bytes(fr_from_be_bytes(a) + fr_from_be_bytes(b))).collect())
    }

    pub fn add_constant(&self, c: Fr) -> Self {
        Self(self.0.iter().map(|a| fr_to_be_bytes(fr_from_be_bytes(a) + c)).collect())
    }

    pub fn hadamard(&self, other: &Self) -> Self {
        assert_eq!(self.0.len(), other.0.len(), "mismatched number of elements");
        Self(self.0.iter().zip(&other.0).map(|(a, b)| fr_to_be_bytes(fr_from_be_bytes(a) * fr_from_be_bytes(b))).collect())
    }

    pub fn inner_product(&self, other: &Self) -> Fr {
        assert_eq!(self.0.len(), other.0.len(), "mismatched number of elements");
        self.0.iter().zip(&other.0).fold(Fr::ZERO, |acc, (a, b)| acc + fr_from_be_bytes(a) * fr_from_be_bytes(b))
    }

    pub fn negate(&self) -> Self {
        Self(self.0.iter().map(|a| fr_to_be_bytes(-fr_from_be_bytes(a))).collect())
    }

    pub fn times(&self, m: Fr) -> Self {
        Self(self.0.iter().map(|a| fr_to_be_bytes(fr_from_be_bytes(a) * m)).collect())
    }

    pub fn invert(&self) -> Self {
        Self(self.0.iter().map(|a| fr_to_be_bytes(fr_from_be_bytes(a).inverse().unwrap())).collect())
    }

    pub fn concat(&self, other: &Self) -> Self {
        let mut v = self.0.clone();
        v.extend_from_slice(&other.0);
        Self(v)
    }

    /// Even/odd index extraction. RAW bytes.
    pub fn extract(&self, parity: bool) -> Self {
        let rem = parity as usize;
        Self(self.0.iter().enumerate().filter(|(i, _)| i % 2 == rem).map(|(_, x)| *x).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fr_reduces_mod_n() {
        // n itself -> 0
        let n = hex::decode(N_HEX).unwrap();
        let f = fr_from_be_bytes(&n);
        assert_eq!(f, Fr::ZERO);
        // n + 1 -> 1
        let mut n1 = n.clone();
        n1[31] += 1;
        let f = fr_from_be_bytes(&n1);
        assert_eq!(f, Fr::ONE);
    }

    #[test]
    fn vector_ops_basic() {
        let mk = |v: u64| -> String {
            let mut b = [0u8; 32];
            b[31] = v as u8;
            hex::encode(b)
        };
        let a = FieldVector::from_hex(&[mk(2), mk(3)]);
        let b = FieldVector::from_hex(&[mk(4), mk(5)]);
        assert_eq!(a.add(&b).to_hex(), vec![mk(6), mk(8)]);
        assert_eq!(a.inner_product(&b), Fr::from(23u64));
        assert_eq!(a.hadamard(&b).to_hex(), vec![mk(8), mk(15)]);
        // flip of 2 elements keeps order (Go quirk: (2-i)%2)
        assert_eq!(a.flip().to_hex(), vec![mk(2), mk(3)]);
    }

    #[test]
    fn raw_preserved_through_identity_ops() {
        // values >= n are NOT reduced by flip/extract (Go behavior)
        let big = "35c8282a292049c4e03540f4d094b9b81d33935dfb7348f71df01313e20b94f8".to_string();
        let small = "bbcca53cfd26b2d9c9492dda624f9cad735048d923617e90744cff464f8b3f2e".to_string();
        let v = FieldVector::from_hex(&[big.clone(), small.clone()]);
        assert_eq!(v.flip().to_hex(), vec![big, small]);
    }
}
