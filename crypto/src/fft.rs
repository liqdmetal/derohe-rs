// SPDX-License-Identifier: BSD-3-Clause
//
//! Number-theoretic FFT + convolution, mirroring derohe
//! `cryptography/crypto/fieldvector.go` (fft_FieldVector,
//! fft_GeneratorVector, Convolution).
//!
//! Uses the primitive 2^28-th root of unity mod n
//! (unity = 14a3074b...46edd), omega = unity^((2^28)/length).

use ark_bn254::Fr;
use ark_ff::Field;

use crate::fieldvector::{fr_from_be_bytes, fr_to_be_bytes, FieldVector};
use crate::pointvector::PointVector;

pub const UNITY_HEX: &str = "14a3074b02521e3b1ed9852e5028452693e87be4e910500c7ba9bbddb2f46edd";

fn pow_mod_hex(base_hex: &str, exp: u64) -> Fr {
    let base = fr_from_be_bytes(&hex::decode(base_hex).expect("valid hex"));
    let mut e = exp;
    let mut acc = Fr::ONE;
    let mut b = base;
    while e > 0 {
        if e & 1 == 1 {
            acc *= b;
        }
        b = b * b;
        e >>= 1;
    }
    acc
}

fn omega_for(length: usize, inverse: bool) -> Fr {
    assert!(length >= 2 && length.is_power_of_two(), "length must be a power of 2");
    let mut omega = pow_mod_hex(UNITY_HEX, (1u64 << 28) / length as u64);
    if inverse {
        omega = omega.inverse().unwrap();
    }
    omega
}

/// fft_FieldVector: recursive radix-2 FFT over field elements mod n.
pub fn fft_fieldvector(input: &FieldVector, inverse: bool) -> FieldVector {
    let length = input.length();
    if length == 1 {
        return input.clone_();
    }
    assert_eq!(length % 2, 0, "length must be multiple of 2");
    let omega = omega_for(length, inverse);
    let even = fft_fieldvector(&input.extract(false), inverse);
    let odd = fft_fieldvector(&input.extract(true), inverse);
    let mut omegas = vec![Fr::ONE];
    for i in 1..length / 2 {
        omegas.push(omegas[i - 1] * omega);
    }
    let omegasv = FieldVector::new(omegas.iter().map(|f| fr_to_be_bytes(*f)).collect());
    // Go: even.Add(odd.Hadamard(omegasv)).Concat(even.Add(odd.Hadamard(omegasv).Negate()))
    let plus = even.add(&odd.hadamard(&omegasv));
    let second = even.add(&odd.hadamard(&omegasv).negate());
    let result = plus.concat(&second);
    if inverse {
        let inv2 = Fr::from(2u64).inverse().unwrap();
        result.times(inv2)
    } else {
        result
    }
}

/// fft_GeneratorVector: same FFT over a vector of G1 points.
pub fn fft_generatorvector(input: &PointVector, inverse: bool) -> PointVector {
    let length = input.len();
    if length == 1 {
        return input.clone();
    }
    assert_eq!(length % 2, 0, "length must be multiple of 2");
    let omega = omega_for(length, inverse);
    let even = fft_generatorvector(&input.extract(false), inverse);
    let odd = fft_generatorvector(&input.extract(true), inverse);
    let mut omegas = vec![Fr::ONE];
    for i in 1..length / 2 {
        omegas.push(omegas[i - 1] * omega);
    }
    let omegasv = FieldVector::new(omegas.iter().map(|f| fr_to_be_bytes(*f)).collect());
    let plus = even.add(&odd.hadamard(&omegasv));
    let second = even.add(&odd.hadamard(&omegasv).negate());
    let result = plus.concat(&second);
    if inverse {
        let inv2 = Fr::from(2u64).inverse().unwrap();
        result.times(inv2)
    } else {
        result
    }
}

/// Convolution(exponent, base): exponent-polynomial applied to a point basis
/// via FFT (Go `Convolution` in fieldvector.go:282-297).
pub fn convolution(exponent: &FieldVector, base: &PointVector) -> PointVector {
    let size = base.len();
    let exponent_fft = fft_fieldvector(&exponent.flip(), false);
    let temp = fft_generatorvector(base, false).hadamard(&exponent_fft);
    let inv2 = Fr::from(2u64).inverse().unwrap();
    let half = temp.slice(0, size / 2).add(&temp.slice(size / 2, size)).times(inv2);
    fft_generatorvector(&half, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::N_HEX;
    
    #[test]
    fn unity_is_primitive() {
        // unity^(2^28) == 1 mod n
        let u = pow_mod_hex(UNITY_HEX, 1 << 28);
        assert_eq!(u, Fr::ONE);
    }

    #[test]
    fn fft_roundtrip() {
        // fft(fft(x, false), true) == x for power-of-2 lengths
        for ln in [2usize, 4, 8, 16] {
            let v: Vec<[u8; 32]> = (0..ln)
                .map(|i| {
                    let mut b = [0u8; 32];
                    b[31] = (i + 1) as u8;
                    b
                })
                .collect();
            let fv = FieldVector::new(v.clone());
            let fwd = fft_fieldvector(&fv, false);
            let back = fft_fieldvector(&fwd, true);
            assert_eq!(back.to_hex(), FieldVector::new(v).to_hex(), "len {ln}");
        }
    }

    #[test]
    fn fft_of_constant_vector_is_delta() {
        // FFT of [c, c, c, c] = [4c, 0, 0, 0]
        let c = {
            let mut b = [0u8; 32];
            b[31] = 3;
            b
        };
        let fv = FieldVector::new(vec![c, c, c, c]);
        let fwd = fft_fieldvector(&fv, false);
        let expect = {
            let mut b = [0u8; 32];
            b[31] = 12;
            fr_to_be_bytes(fr_from_be_bytes(&b))
        };
        let zero = [0u8; 32];
        assert_eq!(fwd.to_hex(), vec![hex::encode(expect), hex::encode(zero), hex::encode(zero), hex::encode(zero)]);
        let _ = N_HEX;
    }
}
