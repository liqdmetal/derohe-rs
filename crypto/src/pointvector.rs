// SPDX-License-Identifier: BSD-3-Clause
//
//! PointVector: vectors of G1 points, mirroring derohe
//! `cryptography/crypto/algebra_pointvector.go`.
//! Supports the ops needed by the FFT and inner-product argument.

use ark_bn254::G1Projective;
use ark_ec::PrimeGroup;
use ark_ff::fields::AdditiveGroup;
use ark_ff::PrimeField;

use crate::fieldvector::{fr_from_be_bytes, FieldVector};

#[derive(Clone, Debug, PartialEq)]
pub struct PointVector(pub Vec<G1Projective>);

impl PointVector {
    pub fn new(v: Vec<G1Projective>) -> Self {
        Self(v)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn slice(&self, start: usize, end: usize) -> Self {
        Self(self.0[start..end].to_vec())
    }

    pub fn extract(&self, parity: bool) -> Self {
        let rem = parity as usize;
        Self(
            self.0
                .iter()
                .enumerate()
                .filter(|(i, _)| i % 2 == rem)
                .map(|(_, x)| *x)
                .collect(),
        )
    }

    pub fn add(&self, other: &Self) -> Self {
        assert_eq!(self.0.len(), other.0.len(), "mismatched number of elements");
        Self(self.0.iter().zip(&other.0).map(|(a, b)| *a + *b).collect())
    }

    pub fn hadamard(&self, exps: &FieldVector) -> Self {
        assert_eq!(self.0.len(), exps.length(), "mismatched number of elements");
        Self(
            self.0
                .iter()
                .zip(&exps.0)
                .map(|(p, e)| p.mul_bigint(fr_from_be_bytes(e).into_bigint()))
                .collect(),
        )
    }

    pub fn negate(&self) -> Self {
        Self(self.0.iter().map(|p| -*p).collect())
    }

    pub fn times(&self, m: ark_bn254::Fr) -> Self {
        Self(
            self.0
                .iter()
                .map(|p| p.mul_bigint(m.into_bigint()))
                .collect(),
        )
    }

    pub fn concat(&self, other: &Self) -> Self {
        let mut v = self.0.clone();
        v.extend_from_slice(&other.0);
        Self(v)
    }

    pub fn sum(&self) -> G1Projective {
        self.0.iter().fold(G1Projective::ZERO, |a, b| a + *b)
    }

    /// Σ points[i]^exps[i], matching Go PointVector.MultiExponentiate.
    pub fn multiexp(&self, exps: &FieldVector) -> G1Projective {
        assert_eq!(self.0.len(), exps.length(), "mismatched number of elements");
        let mut acc = G1Projective::ZERO;
        for (p, e) in self.0.iter().zip(&exps.0) {
            acc += p.mul_bigint(fr_from_be_bytes(e).into_bigint());
        }
        acc
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;

    fn pt(i: u64) -> G1Projective {
        // deterministic distinct points: generator * (i+1)
        G1Projective::generator().mul_bigint([i + 1, 0, 0, 0])
    }

    fn fv(v: &[u64]) -> FieldVector {
        FieldVector::new(
            v.iter()
                .map(|x| {
                    let mut b = [0u8; 32];
                    b[31] = *x as u8;
                    b
                })
                .collect(),
        )
    }

    #[test]
    fn multiexp_matches_sum_of_terms() {
        let pv = PointVector::new(vec![pt(1), pt(2), pt(3)]);
        let exps = fv(&[2, 3, 4]);
        let got = pv.multiexp(&exps);
        let expect = pt(1).mul_bigint([2, 0, 0, 0])
            + pt(2).mul_bigint([3, 0, 0, 0])
            + pt(3).mul_bigint([4, 0, 0, 0]);
        assert_eq!(got, expect);
        let _ = Fr::from(1u64);
    }
}
