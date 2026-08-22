//! Pedersen generator params + commitments, mirroring derohe
//! `cryptography/crypto/algebra_pedersen.go` + `generatorparams.go`.
//!
//! Global (mainnet) params are fixed:
//!   G = HashToPoint(keccak256("DEROG"))
//!   H = HashToPoint(keccak256("DEROH"))
//!   Gs[i] = HashToPoint(keccak256("DEROG" || BE32(i)))   for i in 0..128
//!   Hs[i] = HashToPoint(keccak256("DEROH" || BE32(i)))
//!   GSUM = Σ Gs[i]
//! (Go pads the hex of i to 64 chars then decodes to 32 bytes == BE32(i).)

use ark_bn254::{G1Affine, G1Projective};
use ark_ec::PrimeGroup;
use ark_ff::PrimeField;
use ark_ff::fields::AdditiveGroup;

use crate::curve::{be32_to_bigint, decode_compressed, encode_compressed};
use crate::fieldvector::{fr_from_be_bytes, FieldVector};
use crate::hash_to_point::{base_g, hash_to_point};
use crate::keccak::keccak256;

pub const GLOBAL_VECTOR_COUNT: usize = 128;

#[derive(Clone, Debug)]
pub struct PedersenParams {
    pub g: G1Projective,
    pub h: G1Projective,
    pub gsum: G1Projective,
    pub gs: Vec<G1Projective>,
    pub hs: Vec<G1Projective>,
}

/// Derive the generator params for `count` vector bases.
pub fn generator_params(count: usize) -> PedersenParams {
    let g = base_g();
    let h = hash_to_point(&keccak256(b"DEROH"));
    let mut gs = Vec::with_capacity(count);
    let mut hs = Vec::with_capacity(count);
    let mut gsum = G1Projective::ZERO;
    for i in 0..count {
        let mut seed_g = b"DEROG".to_vec();
        seed_g.extend_from_slice(&be32(i));
        let mut seed_h = b"DEROH".to_vec();
        seed_h.extend_from_slice(&be32(i));
        let gi = hash_to_point(&keccak256(&seed_g));
        let hi = hash_to_point(&keccak256(&seed_h));
        gs.push(gi);
        hs.push(hi);
        gsum += gi;
    }
    PedersenParams { g, h, gsum, gs, hs }
}

/// 32 big-endian bytes of `i` (Go: 64-char zero-padded hex -> 32 bytes).
fn be32(i: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[28..].copy_from_slice(&(i as u32).to_be_bytes());
    out
}

/// Scalar Pedersen: G^value * H^randomness.
pub fn pedersen_commit_scalar(params: &PedersenParams, value: &[u8; 32], r: &[u8; 32]) -> G1Projective {
    let v = be32_to_bigint(value);
    let rb = be32_to_bigint(r);
    params.g.mul_bigint(v) + params.h.mul_bigint(rb)
}

/// Vector Pedersen: H^r + Σ Gs[i]^g[i] + Σ Hs[i]^h[i].
pub fn pedersen_commit(
    params: &PedersenParams,
    gvalues: &FieldVector,
    hvalues: &FieldVector,
    r: &[u8; 32],
) -> G1Projective {
    let rb = be32_to_bigint(r);
    let mut point = params.h.mul_bigint(rb);
    for (gi, g) in params.gs.iter().zip(&gvalues.0) {
        point += gi.mul_bigint(fr_from_be_bytes(g).into_bigint());
    }
    for (hi, h) in params.hs.iter().zip(&hvalues.0) {
        point += hi.mul_bigint(fr_from_be_bytes(h).into_bigint());
    }
    point
}

/// Multi-exponentiation: Σ points[i]^exps[i], matching Go PointVector.MultiExponentiate.
pub fn multi_exp(points: &[G1Projective], exps: &FieldVector) -> G1Projective {
    assert_eq!(points.len(), exps.length(), "mismatched number of elements");
    let mut acc = G1Projective::ZERO;
    for (p, e) in points.iter().zip(&exps.0) {
        acc += p.mul_bigint(fr_from_be_bytes(e).into_bigint());
    }
    acc
}

pub fn point_to_hex(p: &G1Projective) -> String {
    hex::encode(encode_compressed(p))
}

pub fn point_from_hex(h: &str) -> G1Projective {
    decode_compressed(&hex::decode(h).expect("valid hex")).expect("valid point")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;

    #[test]
    fn gsum_matches_sum() {
        let p = generator_params(GLOBAL_VECTOR_COUNT);
        let sum: G1Projective = p.gs.iter().fold(G1Projective::ZERO, |a, b| a + *b);
        assert_eq!(p.gsum, sum);
    }

    #[test]
    fn gs_seed_structure() {
        // Gs[0] = HashToPoint(keccak256("DEROG" + 32 zero bytes))
        let seed = {
            let mut s = b"DEROG".to_vec();
            s.extend_from_slice(&[0u8; 32]);
            s
        };
        let p = generator_params(1);
        assert_eq!(p.gs[0], hash_to_point(&keccak256(&seed)));
    }

    #[test]
    fn vector_commit_roundtrip_is_linear() {
        let p = generator_params(4);
        let mk = |v: u64| {
            let mut b = [0u8; 32];
            b[31] = v as u8;
            b
        };
        let gv = FieldVector::new(vec![mk(1), mk(2), mk(3), mk(4)]);
        let hv = FieldVector::new(vec![mk(5), mk(6), mk(7), mk(8)]);
        let r = [0u8; 32];
        let c1 = pedersen_commit(&p, &gv, &hv, &r);
        // sum of individual scalar terms + H^0 should equal the vector commit
        let mut expect = p.h.mul_bigint(be32_to_bigint(&r));
        for (i, g) in p.gs.iter().enumerate() {
            expect += g.mul_bigint(fr_from_be_bytes(&gv.element(i)).into_bigint());
        }
        for (i, h) in p.hs.iter().enumerate() {
            expect += h.mul_bigint(fr_from_be_bytes(&hv.element(i)).into_bigint());
        }
        assert_eq!(c1, expect);
        let _ = G1Affine::from(c1);
    }
}
