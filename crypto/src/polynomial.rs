// SPDX-License-Identifier: BSD-3-Clause
//
//! Polynomial arithmetic, mirroring derohe `cryptography/crypto/polynomial.go`.
//!
//! Quirk: `Polynomial.Mul` only correctly multiplies by a binomial (x + c)
//! whose linear coefficient is exactly 1 (Go checks `m.coefficients[1] == 1`).
//! It is used in the bulletproof recursion where every factor is such a
//! binomial (RecursivePolynomials). Replicated exactly.

use ark_bn254::Fr;
use ark_ff::{Field, One};

use crate::fieldvector::{fr_from_be_bytes, fr_to_be_bytes};

#[derive(Clone, Debug, PartialEq)]
pub struct Polynomial {
    pub coefficients: Vec<[u8; 32]>, // raw 32-byte BE, reduced mod n by Mul
}

impl Polynomial {
    /// NewPolynomial: nil input -> [1]; otherwise wraps the coefficients.
    pub fn new(input: Option<Vec<[u8; 32]>>) -> Self {
        match input {
            None => {
                let mut one = [0u8; 32];
                one[31] = 1;
                Polynomial { coefficients: vec![one] }
            }
            Some(c) => Polynomial { coefficients: c },
        }
    }

    pub fn length(&self) -> usize {
        self.coefficients.len()
    }

    /// Go Polynomial.Mul: multiply by (x + m0) when m[1] == 1.
    ///   product[i] = p[i]*m0 (+ p[i-1] if m[1]==1), product[len(p)] = 0 (+p[len-1])
    pub fn mul(&self, m: &Polynomial) -> Polynomial {
        let m0 = fr_from_be_bytes(&m.coefficients[0]);
        let mut product: Vec<[u8; 32]> = self
            .coefficients
            .iter()
            .map(|c| fr_to_be_bytes(fr_from_be_bytes(c) * m0))
            .collect();
        product.push([0u8; 32]);
        let m1 = fr_from_be_bytes(&m.coefficients[1]);
        if m1 == Fr::ONE {
            for i in 1..product.len() {
                product[i] = fr_to_be_bytes(fr_from_be_bytes(&product[i]) + fr_from_be_bytes(&self.coefficients[i - 1]));
            }
        }
        Polynomial { coefficients: product }
    }
}

/// RecursivePolynomials: builds 2^n binomial-product polynomials from a/b.
/// a values are arbitrary; b values must be 0/1 for Mul to behave.
/// Order: depth-first, left (=-atop branch) before right (=atop branch).
pub fn recursive_polynomials(accum: &Polynomial, a: &[Fr], b: &[Fr]) -> Vec<Polynomial> {
    let mut list = Vec::new();
    fn rec(list: &mut Vec<Polynomial>, accum: &Polynomial, a: &[Fr], b: &[Fr]) {
        if a.is_empty() {
            list.push(accum.clone());
            return;
        }
        let atop = a[a.len() - 1];
        let btop = b[b.len() - 1];
        let left = Polynomial::new(Some(vec![
            fr_to_be_bytes(-atop),
            fr_to_be_bytes(Fr::ONE - btop),
        ]));
        let right = Polynomial::new(Some(vec![
            fr_to_be_bytes(atop),
            fr_to_be_bytes(btop),
        ]));
        rec(list, &accum.mul(&left), &a[..a.len() - 1], &b[..b.len() - 1]);
        rec(list, &accum.mul(&right), &a[..a.len() - 1], &b[..b.len() - 1]);
    }
    rec(&mut list, accum, a, b);
    list
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fieldvector::fr_from_hex;

    fn coeff(v: u64) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[31] = v as u8;
        b
    }

    #[test]
    fn mul_by_binomial() {
        // (2x + 3) * (x + 5) = 2x² + 13x + 15
        let p = Polynomial::new(Some(vec![coeff(3), coeff(2)]));
        let m = Polynomial::new(Some(vec![coeff(5), coeff(1)]));
        let prod = p.mul(&m);
        let hex = |v: u64| hex::encode(coeff(v));
        assert_eq!(prod.coefficients.iter().map(|c| hex::encode(c)).collect::<Vec<_>>(),
                   vec![hex(15), hex(13), hex(2)]);
    }

    #[test]
    fn recursive_polynomials_count() {
        let a = vec![fr_from_hex(&hex::encode(coeff(1))), fr_from_hex(&hex::encode(coeff(2))), fr_from_hex(&hex::encode(coeff(3)))];
        let b = vec![fr_from_hex(&hex::encode(coeff(0))), fr_from_hex(&hex::encode(coeff(1))), fr_from_hex(&hex::encode(coeff(1)))];
        let list = recursive_polynomials(&Polynomial::new(None), &a, &b);
        assert_eq!(list.len(), 8);
        // each polynomial has 4 coefficients (3 binomials + trailing)
        for p in &list {
            assert_eq!(p.length(), 4);
        }
    }
}
