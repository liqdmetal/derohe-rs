// SPDX-License-Identifier: BSD-3-Clause
//
//! Try-and-increment hash-to-curve, mirroring derohe
//! `cryptography/crypto/hashtopoint.go` exactly:
//!   x = seed mod n            (reduced by GROUP order)
//!   loop: y = (x^3+3)^((p+1)/4) mod p; if y^2 == x^3+3 return (x,y); x += 1 mod p
//!
//! DERO-specific quirk: the initial reduction is mod n (group order), the
//! increment loop wraps mod p (field order). p and n differ by ~5e38, so this
//! only matters for seeds in [n, p), but it is replicated for exactness.

use ark_bn254::{Fq, G1Affine, G1Projective};
use ark_ff::{Field, One, PrimeField};
use num_bigint::BigUint;

use crate::curve::{be32_to_bigint, bigint_from_hex, N_HEX};

fn x_to_y(x: Fq) -> (Fq, bool) {
    let rhs = x.square() * x + Fq::from(3u32);
    // (p+1)/4
    let exp = bigint_from_hex("0c19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f52");
    let y = rhs.pow(&exp);
    (y, y.square() == rhs)
}

/// HashToPoint(seed) for a 32-byte seed, exactly as Go `crypto.HashToPoint`.
pub fn hash_to_point(seed: &[u8; 32]) -> G1Projective {
    // x = seed mod n (group order), then try-and-increment mod p (field order)
    let seed_bu = BigUint::from_bytes_be(seed);
    let n_bu = BigUint::from_bytes_be(&hex::decode(N_HEX).expect("valid n hex"));
    let x_mod_n = seed_bu % n_bu;
    let x_bytes = x_mod_n.to_bytes_be();
    let mut xb = [0u8; 32];
    xb[32 - x_bytes.len()..].copy_from_slice(&x_bytes);
    let mut x = Fq::from_bigint(be32_to_bigint(&xb)).expect("x < n < p");
    loop {
        let (y, ok) = x_to_y(x);
        if ok {
            return G1Affine::new_unchecked(x, y).into();
        }
        x += Fq::one();
    }
}

/// The protocol base point: G = HashToPoint(keccak256("DERO" + "G")).
pub fn base_g() -> G1Projective {
    let seed = crate::keccak::keccak256(b"DEROG");
    hash_to_point(&seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::{decode_compressed, encode_compressed};
    use hex::FromHex;

    #[test]
    fn hashtopoint_of_zero_is_well_defined() {
        let p = hash_to_point(&[0u8; 32]);
        let enc = encode_compressed(&p);
        assert!(decode_compressed(&enc).is_ok());
    }

    #[test]
    fn base_g_roundtrips() {
        // G = HashToPoint(keccak256("DEROG")); exact value is pinned by the
        // differential harness against the Go oracle.
        let g = base_g();
        let enc = encode_compressed(&g);
        assert_eq!(decode_compressed(&enc).unwrap(), g);
    }

    #[test]
    fn base_g_pinned_by_go_oracle() {
        // Oracle-pinned reference value (Go oracle, 2026-08-22): must never
        // change without a corresponding reference change.
        use hex::FromHex;
        let g = base_g();
        let enc = encode_compressed(&g);
        let expect =
            <[u8; 33]>::from_hex("02eacfbf92b94015c9b0b3d901dae37ec68f74dea7e4484c76d505aade4ad7c001")
                .unwrap();
        assert_eq!(&enc[..], &expect);
    }
}
