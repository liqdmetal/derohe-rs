// SPDX-License-Identifier: BSD-3-Clause
//
//! Inner-product argument (Bulletproofs-style), mirroring derohe
//! `cryptography/crypto/proof_innerproduct.go`.
//!
//! The recursive folding is fully deterministic given (as, bs, salt):
//!   L = <g_right, as_left> + <h_left, bs_right> + u·cL
//!   R = <g_left, as_right> + <h_right, bs_left> + u·cR
//!   x = reducedhash(salt || L.Marshal() || R.Marshal())   (UNCOMPRESSED!)
//! Challenge transcripts use the UNCOMPRESSED 64-byte point encoding.
//! Honest P for a length-n statement: Σ Gs[i]^as[i] + Σ Hs[i]^bs[i] + u^(as·bs).

use ark_bn254::{G1Projective, G1Affine};
use ark_ec::PrimeGroup;
use ark_ff::{Field, PrimeField};
use ark_ff::fields::AdditiveGroup;

use crate::curve::{encode_compressed, encode_uncompressed};
use crate::fieldvector::{fr_from_be_bytes, fr_to_be_bytes, FieldVector};
use crate::keccak::keccak256;
use crate::pedersen::PedersenParams;
use crate::pointvector::PointVector;

#[derive(Clone, Debug, PartialEq)]
pub struct InnerProduct {
    pub a: [u8; 32],
    pub b: [u8; 32],
    pub ls: Vec<G1Projective>,
    pub rs: Vec<G1Projective>,
}

/// reducedhash(input) = keccak256(input) mod n.
pub fn reduced_hash(input: &[u8]) -> ark_bn254::Fr {
    fr_from_be_bytes(&keccak256(input))
}

/// Deterministic inner-product proof generation (Go generateInnerProductProof).
pub fn generate(
    params: &PedersenParams,
    p: &G1Projective,
    as_: &FieldVector,
    bs: &FieldVector,
    prev_challenge: &[u8; 32],
) -> InnerProduct {
    let n = as_.length();
    if n == 1 {
        return InnerProduct { a: as_.element(0), b: bs.element(0), ls: vec![], rs: vec![] };
    }
    let nprime = n / 2;
    let as_left = as_.slice(0, nprime);
    let as_right = as_.slice(nprime, n);
    let bs_left = bs.slice(0, nprime);
    let bs_right = bs.slice(nprime, n);
    let g_left = PointVector::new(params.gs[0..nprime].to_vec());
    let g_right = PointVector::new(params.gs[nprime..n].to_vec());
    let h_left = PointVector::new(params.hs[0..nprime].to_vec());
    let h_right = PointVector::new(params.hs[nprime..n].to_vec());

    let cl = as_left.inner_product(&bs_right);
    let cr = as_right.inner_product(&bs_left);
    let u = params.h;

    // L = gRight·asLeft + hLeft·bsRight + u*cL
    let mut l = g_right.multiexp(&as_left) + h_left.multiexp(&bs_right);
    l += u.mul_bigint(cl.into_bigint());
    // R = gLeft·asRight + hRight·bsLeft + u*cR
    let mut r = g_left.multiexp(&as_right) + h_right.multiexp(&bs_left);
    r += u.mul_bigint(cr.into_bigint());

    // x = reducedhash(prev_challenge || L.Marshal() || R.Marshal()) — uncompressed
    let mut input = Vec::with_capacity(32 + 64 + 64);
    input.extend_from_slice(prev_challenge);
    input.extend_from_slice(&encode_uncompressed(&l));
    input.extend_from_slice(&encode_uncompressed(&r));
    let x = reduced_hash(&input);
    let xinv = x.inverse().expect("x invertible mod n");

    let gprime = g_left.times(xinv).add(&g_right.times(x));
    let hprime = h_left.times(x).add(&h_right.times(xinv));
    let aprime = as_left.times(x).add(&as_right.times(xinv));
    let bprime = bs_left.times(xinv).add(&bs_right.times(x));

    // basePrime = GeneratorParams3(u, gprime, hprime): G recomputed (unused), H = u
    let base_prime = PedersenParams {
        g: params.g,
        h: u,
        gsum: G1Projective::ZERO,
        gs: gprime.0,
        hs: hprime.0,
    };

    // PPrime = L·x² + R·xinv² + P
    let x2 = x * x;
    let xinv2 = xinv * xinv;
    let pprime = l.mul_bigint(x2.into_bigint()) + r.mul_bigint(xinv2.into_bigint()) + *p;

    let mut ip = generate(&base_prime, &pprime, &aprime, &bprime, &fr_to_be_bytes(x));
    ip.ls.insert(0, l);
    ip.rs.insert(0, r);
    ip
}

/// Go InnerProduct.Serialize: a(32) || b(32) || (L(33) || R(33)) per round.
pub fn serialize(ip: &InnerProduct) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + 66 * ip.ls.len());
    out.extend_from_slice(&ip.a);
    out.extend_from_slice(&ip.b);
    for (l, r) in ip.ls.iter().zip(&ip.rs) {
        out.extend_from_slice(&encode_compressed(l));
        out.extend_from_slice(&encode_compressed(r));
    }
    out
}

/// Go InnerProduct.Verify: recompute challenges, fold P, check the equation.
pub fn verify(
    ip: &InnerProduct,
    hs: &[G1Projective],
    u: &G1Projective,
    p: &G1Projective,
    salt: &[u8; 32],
    params: &PedersenParams,
) -> bool {
    let log_n = ip.ls.len();
    if ip.ls.len() != ip.rs.len() {
        return false;
    }
    let n = 1usize << log_n;

    let mut o = *salt;
    let mut challenges: Vec<ark_bn254::Fr> = Vec::with_capacity(log_n);
    let mut p_folded = *p;
    for i in 0..log_n {
        let mut input = Vec::with_capacity(32 + 64 + 64);
        input.extend_from_slice(&o);
        input.extend_from_slice(&encode_uncompressed(&ip.ls[i]));
        input.extend_from_slice(&encode_uncompressed(&ip.rs[i]));
        o = fr_to_be_bytes(reduced_hash(&input));
        let oi = fr_from_be_bytes(&o);
        challenges.push(oi);
        let o_inv = oi.inverse().expect("challenge invertible");
        let o2 = oi * oi;
        let o_inv2 = o_inv * o_inv;
        p_folded = ip.ls[i].mul_bigint(o2.into_bigint())
            + ip.rs[i].mul_bigint(o_inv2.into_bigint())
            + p_folded;
    }

    let mut exp = ark_bn254::Fr::ONE;
    for c in &challenges {
        exp *= *c;
    }
    let exp_inv = exp.inverse().expect("product invertible");

    let mut exponents = vec![ark_bn254::Fr::ZERO; n];
    exponents[0] = exp_inv;
    let mut bits = vec![false; n];
    for i in 0..n / 2 {
        let mut j: usize = 0;
        while (1usize << j) + i < n {
            let i1 = (1usize << j) + i;
            if !bits[i1] {
                let temp = challenges[log_n - 1 - j] * challenges[log_n - 1 - j];
                exponents[i1] = exponents[i] * temp;
                bits[i1] = true;
            }
            j += 1;
        }
    }

    let a_fr = fr_from_be_bytes(&ip.a);
    let b_fr = fr_from_be_bytes(&ip.b);

    let mut gtemp = G1Projective::ZERO;
    let mut htemp = G1Projective::ZERO;
    for i in 0..n {
        gtemp += params.gs[i].mul_bigint(exponents[i].into_bigint());
        htemp += hs[i].mul_bigint(exponents[n - 1 - i].into_bigint());
    }
    gtemp = gtemp.mul_bigint(a_fr.into_bigint());
    htemp = htemp.mul_bigint(b_fr.into_bigint());
    let utemp = u.mul_bigint((a_fr * b_fr).into_bigint());

    let p_calculated = gtemp + htemp + utemp;
    p_calculated == p_folded
}

/// Build the honest P for a length-n statement (used by the oracle ops).
pub fn honest_p(params: &PedersenParams, as_: &FieldVector, bs: &FieldVector) -> G1Projective {
    let n = as_.length();
    let gsn = PointVector::new(params.gs[0..n].to_vec());
    let hsn = PointVector::new(params.hs[0..n].to_vec());
    let mut p = gsn.multiexp(as_) + hsn.multiexp(bs);
    p += params.h.mul_bigint(as_.inner_product(bs).into_bigint());
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::be32_to_bigint;
    use crate::pedersen::generator_params;

    fn mk(v: u64) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[31] = v as u8;
        b
    }

    #[test]
    fn generate_verify_roundtrip_n2() {
        let params = generator_params(128);
        let as_ = FieldVector::new(vec![mk(3), mk(4)]);
        let bs = FieldVector::new(vec![mk(5), mk(6)]);
        let salt = mk(42);
        let p = honest_p(&params, &as_, &bs);
        let ip = generate(&params, &p, &as_, &bs, &salt);
        assert_eq!(ip.ls.len(), 1);
        let hs = params.hs[0..2].to_vec();
        assert!(verify(&ip, &hs, &params.h, &p, &salt, &params));
        // tampered proof must fail
        let mut bad = ip.clone();
        bad.a = mk(7);
        assert!(!verify(&bad, &hs, &params.h, &p, &salt, &params));
    }

    #[test]
    fn generate_verify_roundtrip_n128() {
        let params = generator_params(128);
        let as_ = FieldVector::new((1u64..=128).map(mk).collect());
        let bs = FieldVector::new((129u64..=256).map(mk).collect());
        let salt = mk(9);
        let p = honest_p(&params, &as_, &bs);
        let ip = generate(&params, &p, &as_, &bs, &salt);
        assert_eq!(ip.ls.len(), 7);
        assert!(verify(&ip, &params.hs, &params.h, &p, &salt, &params));
        let _ = G1Affine::from(p);
        let _ = be32_to_bigint(&mk(1));
    }
}
