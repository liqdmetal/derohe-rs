//! Aggregate bulletproof (range + ring proof), mirroring derohe
//! `cryptography/crypto/proof_generate.go` + `proof_verify.go`.
//!
//! The prover is deterministic given an injected randomness stream (the 11
//! RandomScalarFixed sites in GenerateProof, consumed in exact call order),
//! so proofs can be differentially compared byte-for-byte with the Go
//! reference. The verifier is fully self-contained (reconstructs everything
//! from the proof + statement), so cross-verification also works: Go accepts
//! Rust proofs and vice versa.
//!
//! All challenge hashes are keccak256 reduced mod n; transcripts use
//! UNCOMPRESSED 64-byte point encodings (matching the Go Marshal() calls).

use ark_bn254::{Fr, G1Projective};
use ark_ec::PrimeGroup;
use ark_ff::{Field, PrimeField};
use ark_ff::fields::AdditiveGroup;

use crate::curve::{encode_compressed, encode_uncompressed};
use crate::elgamal::ElGamal;
use crate::fft;
use crate::fieldvector::{fr_from_be_bytes, fr_to_be_bytes, FieldVector};
use crate::hash_to_point::base_g;
use crate::innerproduct::{self, reduced_hash};
use crate::keccak::keccak256;
use crate::pedersen::{generator_params, PedersenParams};
use crate::pointvector::PointVector;
use crate::polynomial::{recursive_polynomials, Polynomial};

// ---------------------------------------------------------------------------
// Deterministic randomness source
// ---------------------------------------------------------------------------

/// Pops 32 bytes per draw, reduces mod n, maps 0 -> 1 (matching the Go
/// RANDOM_OVERRIDE in the reference's random.go).
#[derive(Clone)]
pub struct RandSource(pub Vec<u8>);

impl RandSource {
    pub fn next(&mut self) -> Fr {
        assert!(self.0.len() >= 32, "randomness exhausted");
        let v = fr_from_be_bytes(&self.0[..32]);
        self.0.drain(..32);
        if v == Fr::ZERO { Fr::ONE } else { v }
    }
}

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

pub struct Witness {
    pub secret_key: Fr,
    pub r: Fr,
    pub transfer_amount: u64,
    pub balance: u64,
    pub index: [usize; 2],
}

#[derive(Clone)]
pub struct Statement {
    pub publickeylist: Vec<G1Projective>,
    pub c: Vec<G1Projective>,   // commitments (Left of the ElGamal pair)
    pub cln: Vec<G1Projective>, // ring pair lefts
    pub crn: Vec<G1Projective>, // ring pair rights
    pub d: G1Projective,
    pub roothash: [u8; 32],
    pub fees: u64,
}

#[derive(Clone)]
pub struct Proof {
    pub ba: G1Projective,
    pub bs: G1Projective,
    pub a: G1Projective,
    pub b: G1Projective,
    pub clng: Vec<G1Projective>,
    pub crng: Vec<G1Projective>,
    pub c_0g: Vec<G1Projective>,
    pub dg: Vec<G1Projective>,
    pub y_0g: Vec<G1Projective>,
    pub gg: Vec<G1Projective>,
    pub c_xg: Vec<G1Projective>,
    pub y_xg: Vec<G1Projective>,
    pub u: G1Projective,
    pub f: FieldVector,
    pub z_a: Fr,
    pub t_1: G1Projective,
    pub t_2: G1Projective,
    pub that: Fr,
    pub mu: Fr,
    pub c: Fr,
    pub s_sk: Fr,
    pub s_r: Fr,
    pub s_b: Fr,
    pub s_tau: Fr,
    pub ip: innerproduct::InnerProduct,
}

// ---------------------------------------------------------------------------
// Helpers (mirror the Go package functions)
// ---------------------------------------------------------------------------

fn pedersen_vector_commit(p: &PedersenParams, gv: &FieldVector, hv: &FieldVector, r: Fr) -> G1Projective {
    let mut point = p.h.mul_bigint(r.into_bigint());
    for (gi, g) in p.gs.iter().zip(&gv.0) {
        point += gi.mul_bigint(fr_from_be_bytes(g).into_bigint());
    }
    for (hi, h) in p.hs.iter().zip(&hv.0) {
        point += hi.mul_bigint(fr_from_be_bytes(h).into_bigint());
    }
    point
}

fn pedersen_commit_scalar(g: &G1Projective, h: &G1Projective, value: Fr, r: Fr) -> G1Projective {
    g.mul_bigint(value.into_bigint()) + h.mul_bigint(r.into_bigint())
}

fn multiexp_points(points: &[G1Projective], exps: &FieldVector) -> G1Projective {
    let mut acc = G1Projective::ZERO;
    for (p, e) in points.iter().zip(&exps.0) {
        acc += p.mul_bigint(fr_from_be_bytes(e).into_bigint());
    }
    acc
}

fn elgamal_commit(key: &G1Projective, value: Fr, r: Fr) -> (ElGamal, Fr) {
    let g = base_g();
    (
        ElGamal::new(
            g.mul_bigint(value.into_bigint()) + key.mul_bigint(r.into_bigint()),
            g.mul_bigint(r.into_bigint()),
        ),
        r,
    )
}

/// Σ e[i]^exp[i] over ElGamal ciphertexts (both sides).
fn elgamal_multiexp(e: &[ElGamal], exps: &FieldVector) -> ElGamal {
    let mut acc = ElGamal::new(G1Projective::ZERO, G1Projective::ZERO);
    for (ei, x) in e.iter().zip(&exps.0) {
        let f = fr_from_be_bytes(x);
        acc = acc.add(&ElGamal::new(ei.left.mul_bigint(f.into_bigint()), ei.right.mul_bigint(f.into_bigint())));
    }
    acc
}

/// ba[i] = bit i of index[0] (i < m), bit (i-m) of index[1] (i >= m) —
/// equivalent to Go's reverse(fmt.Sprintf("%0*m%0*m", m, i1, m, i0)).
fn witness_bits(i0: usize, i1: usize, m: usize) -> Vec<bool> {
    (0..2 * m)
        .map(|i| if i < m { ((i0 >> i) & 1) == 1 } else { ((i1 >> (i - m)) & 1) == 1 })
        .collect()
}

/// Go assemblepolynomials / recursivepolynomials (proof_verify.go:522-554):
///   result[j][0] = Π_{k=0}^{m-1} f[k][bit k of j]
///   result[j][1] = Π_{k=m}^{2m-1} f[k][bit (k-m) of j]
/// Implemented as the exact Go recursion to be safe.
fn assemblepolynomials(f: &[[Fr; 2]]) -> Vec<[Fr; 2]> {
    let m = f.len() / 2;
    let n = 1usize << m;
    let mut result = vec![[Fr::ZERO, Fr::ZERO]; n];
    fn rec(baseline: usize, current: usize, accum: Fr, f: &[[Fr; 2]]) -> Vec<Fr> {
        let size = 1usize << (current - baseline);
        if current == baseline {
            return vec![accum];
        }
        let current = current - 1;
        let left = rec(baseline, current, accum * f[current][0], f);
        let right = rec(baseline, current, accum * f[current][1], f);
        let mut out = vec![Fr::ZERO; size];
        out[..size / 2].copy_from_slice(&left);
        out[size / 2..].copy_from_slice(&right);
        out
    }
    for i in 0..2 {
        let half = rec(i * m, (i + 1) * m, Fr::ONE, f);
        for j in 0..n {
            result[j][i] = half[j];
        }
    }
    result
}

/// FieldVectorPolynomial + InnerProduct (fieldvector.go:27-75).
struct FvPoly {
    coefficients: Vec<FieldVector>,
}

impl FvPoly {
    fn evaluate(&self, x: Fr) -> FieldVector {
        let mut result = self.coefficients[0].clone_();
        let mut acc = x;
        for i in 1..self.coefficients.len() {
            result = result.add(&self.coefficients[i].times(acc));
            acc *= x;
        }
        result
    }
    fn inner_product(&self, other: &FvPoly) -> Vec<Fr> {
        let rl = self.coefficients.len() + other.coefficients.len() - 1;
        let mut result = vec![Fr::ZERO; rl];
        for (i, a) in self.coefficients.iter().enumerate() {
            for (j, b) in other.coefficients.iter().enumerate() {
                result[i + j] += a.inner_product(b);
            }
        }
        result
    }
}

/// hashmash1: reducedhash(v || CLnG.Marshal || CRnG || C_0G || DG || y_0G ||
/// gG || C_XG || y_XG) — all uncompressed.
fn hashmash1(v: Fr, pts: &[&[G1Projective]]) -> Fr {
    let mut input = fr_to_be_bytes(v).to_vec();
    for arr in pts {
        for p in arr.iter() {
            input.extend_from_slice(&encode_uncompressed(p));
        }
    }
    reduced_hash(&input)
}

// ---------------------------------------------------------------------------
// Prove
// ---------------------------------------------------------------------------

pub fn generate_proof(
    scid: &[u8; 32],
    scid_index: i32,
    s: &Statement,
    w: &Witness,
    u: &G1Projective,
    txid: &[u8; 32],
    burn_value: u64,
    rand_bytes: &[u8],
) -> Proof {
    let mut rng = RandSource(rand_bytes.to_vec());
    let params = generator_params(128);
    let g = base_g();

    let statementhash = reduced_hash(txid);

    // 128-bit range: number = balance << 64 | transfer, LSB-first bits.
    let number = ((w.balance as u128) << 64) | (w.transfer_amount as u128);
    let al: Vec<Fr> = (0..128).map(|i| if (number >> i) & 1 == 1 { Fr::ONE } else { Fr::ZERO }).collect();
    let ar: Vec<Fr> = al.iter().map(|b| *b - Fr::ONE).collect();
    let al_fv = FieldVector::new(al.iter().map(|f| fr_to_be_bytes(*f)).collect());
    let ar_fv = FieldVector::new(ar.iter().map(|f| fr_to_be_bytes(*f)).collect());

    // Randomness draw order (matches Go GenerateProof):
    //   BA, sL(128), sR(128), BS, aa, A, B, phi, chi, psi, C_XG, T1, T2,
    //   k_sk, k_r, k_b, k_tau
    let ba_rand = rng.next();
    let s_l: Vec<[u8; 32]> = (0..128).map(|_| fr_to_be_bytes(rng.next())).collect();
    let s_r: Vec<[u8; 32]> = (0..128).map(|_| fr_to_be_bytes(rng.next())).collect();
    let bs_rand = rng.next();
    let ba = pedersen_vector_commit(&params, &al_fv, &ar_fv, ba_rand);
    let bs = pedersen_vector_commit(&params, &FieldVector::new(s_l.clone()), &FieldVector::new(s_r.clone()), bs_rand);

    let n = s.publickeylist.len();
    assert!(n >= 2 && n.is_power_of_two(), "publickeylist must be a power of 2");
    let m = (n as f64).log2() as usize;

    // aa (len 2m): aa[0]=aa[m]=0; Go draws only the 2m-2 other positions
    let aa_draws: Vec<Fr> = (0..2 * m - 2).map(|_| rng.next()).collect();
    let mut aa: Vec<Fr> = vec![Fr::ZERO; 2 * m];
    {
        let mut d = 0;
        for i in 0..2 * m {
            if i != 0 && i != m {
                aa[i] = aa_draws[d];
                d += 1;
            }
        }
    }
    let bits = witness_bits(w.index[0], w.index[1], m);
    let ba_bits: Vec<Fr> = bits.iter().map(|b| if *b { Fr::ONE } else { Fr::ZERO }).collect();
    let bspecial: Vec<Fr> = bits.iter().map(|b| if *b { -Fr::ONE } else { Fr::ONE }).collect();

    let a = FieldVector::new(aa.iter().map(|f| fr_to_be_bytes(*f)).collect());
    let b = FieldVector::new(ba_bits.iter().map(|f| fr_to_be_bytes(*f)).collect());
    let c_vec = a.hadamard(&FieldVector::new(bspecial.iter().map(|f| fr_to_be_bytes(*f)).collect()));
    let d_vec = a.hadamard(&a).negate();
    let a0am = a.element_fr(0) * a.element_fr(m);
    let e = FieldVector::new(vec![fr_to_be_bytes(a0am), fr_to_be_bytes(a0am)]);
    let bm = b.element_fr(m).into_bigint().0[0] as usize; // 0 or 1
    let b0 = b.element_fr(0).into_bigint().0[0] as usize;
    let f_vec = FieldVector::new(vec![
        fr_to_be_bytes(a.element_fr(bm * m)),
        fr_to_be_bytes(-a.element_fr(b0 * m)),
    ]);

    let a_rand = rng.next();
    let b_rand = rng.next();
    let proof_a = pedersen_vector_commit(&params, &a, &d_vec.concat(&e), a_rand);
    let proof_b = pedersen_vector_commit(&params, &b, &c_vec.concat(&f_vec), b_rand);

    let v = reduced_hash(
        &[fr_to_be_bytes(statementhash).as_slice(), &encode_uncompressed(&ba), &encode_uncompressed(&bs), &encode_uncompressed(&proof_a), &encode_uncompressed(&proof_b)].concat(),
    );

    // RecursivePolynomials matrices, transposed (P[i][j] = Pi[j][i])
    let a_frs: Vec<Fr> = (0..2 * m).map(|i| a.element_fr(i)).collect();
    let b_frs: Vec<Fr> = (0..2 * m).map(|i| b.element_fr(i)).collect();
    let pi = recursive_polynomials(&Polynomial::new(None), &a_frs[..m], &b_frs[..m]);
    let qi = recursive_polynomials(&Polynomial::new(None), &a_frs[m..], &b_frs[m..]);
    let mut p_mat: Vec<Vec<Fr>> = vec![vec![Fr::ZERO; pi.len()]; m];
    let mut q_mat: Vec<Vec<Fr>> = vec![vec![Fr::ZERO; qi.len()]; m];
    for i in 0..m {
        for (j, pj) in pi.iter().enumerate() {
            p_mat[i][j] = fr_from_be_bytes(&pj.coefficients[i]);
        }
        for (j, qj) in qi.iter().enumerate() {
            q_mat[i][j] = fr_from_be_bytes(&qj.coefficients[i]);
        }
    }

    // phi/chi/psi: m ElGamal commits to pubkey[index0], value 0
    let pk0 = s.publickeylist[w.index[0]];
    let phi: Vec<(ElGamal, Fr)> = (0..m).map(|_| elgamal_commit(&pk0, Fr::ZERO, rng.next())).collect();
    let chi: Vec<(ElGamal, Fr)> = (0..m).map(|_| elgamal_commit(&pk0, Fr::ZERO, rng.next())).collect();
    let psi: Vec<(ElGamal, Fr)> = (0..m).map(|_| elgamal_commit(&pk0, Fr::ZERO, rng.next())).collect();

    // ring ElGamal pairs
    let cn: Vec<ElGamal> = (0..n).map(|i| ElGamal::new(s.cln[i], s.crn[i])).collect();
    let c_pairs: Vec<ElGamal> = (0..n).map(|i| ElGamal::new(s.c[i], s.d)).collect();

    let mut cn_g: Vec<ElGamal> = Vec::with_capacity(m);
    let mut c_0g: Vec<ElGamal> = Vec::with_capacity(m);
    let mut y_0g: Vec<ElGamal> = Vec::with_capacity(m);
    for i in 0..m {
        let pi_fv = FieldVector::new(p_mat[i].iter().map(|f| fr_to_be_bytes(*f)).collect());
        cn_g.push(elgamal_multiexp(&cn, &pi_fv).add(&phi[i].0));
        let left = multiexp_points(&s.c, &pi_fv) + chi[i].0.left;
        c_0g.push(ElGamal::new(left, chi[i].0.right));
        let left = multiexp_points(&s.publickeylist, &pi_fv) + psi[i].0.left;
        y_0g.push(ElGamal::new(left, psi[i].0.right));
    }

    // C_XG: m ElGamal commits to C[0].Right (= D), value 0, then the vPow loop
    let mut c_xg: Vec<ElGamal> = (0..m).map(|_| elgamal_commit(&c_pairs[0].right, Fr::ZERO, rng.next()).0).collect();
    let mut v_pow = Fr::ONE;
    for i in 0..n {
        let poly: &Vec<Vec<Fr>> = if i % 2 == 0 { &p_mat } else { &q_mat };
        for j in 0..m {
            let amount = Fr::from(w.transfer_amount as u64);
            let amount_fees = Fr::from((s.fees + burn_value) as u64);
            let left = (-amount - amount_fees) * poly[j][(w.index[0] + n - (i - i % 2)) % n];
            let right = amount * poly[j][(w.index[1] + n - (i - i % 2)) % n];
            let mul = v_pow * (left + right);
            c_xg[j] = c_xg[j].plus(&fr_to_be_bytes(mul));
        }
        if i != 0 {
            v_pow *= v;
        }
    }

    // proof point arrays
    let mut clng = Vec::with_capacity(m);
    let mut crng = Vec::with_capacity(m);
    let mut c_0gv = Vec::with_capacity(m);
    let mut dgv = Vec::with_capacity(m);
    let mut y_0gv = Vec::with_capacity(m);
    let mut ggv = Vec::with_capacity(m);
    let mut c_xgv = Vec::with_capacity(m);
    let mut y_xgv = Vec::with_capacity(m);
    for i in 0..m {
        clng.push(cn_g[i].left);
        crng.push(cn_g[i].right);
        c_0gv.push(c_0g[i].left);
        dgv.push(c_0g[i].right);
        y_0gv.push(y_0g[i].left);
        ggv.push(y_0g[i].right);
        c_xgv.push(c_xg[i].left);
        y_xgv.push(c_xg[i].right);
    }

    let w_chal = hashmash1(v, &[&clng, &crng, &c_0gv, &dgv, &y_0gv, &ggv, &c_xgv, &y_xgv]);

    // f = b*w + a; z_A = B_rand*w + A_rand (Go: proof_B_internal.Randomness, NOT BS)
    let f_fv = b.times(w_chal).add(&a);
    let z_a = b_rand * w_chal + a_rand;

    let y = reduced_hash(&fr_to_be_bytes(w_chal));
    let ys: Vec<Fr> = (0..128).scan(Fr::ONE, |acc, _| { let cur = *acc; *acc *= y; Some(cur) }).collect();
    let z = reduced_hash(&fr_to_be_bytes(y));
    let zs = vec![z * z, z * z * z];
    let twos: Vec<Fr> = (0..64).scan(Fr::ONE, |acc, _| { let cur = *acc; *acc *= Fr::from(2u64); Some(cur) }).collect();
    let two_times_zs: Vec<Fr> = zs.iter().flat_map(|zi| twos.iter().map(move |t| *zi * *t)).collect();

    let ys_fv = FieldVector::new(ys.iter().map(|f| fr_to_be_bytes(*f)).collect());
    let tmp = al_fv.add_constant(-z);
    let l_poly = FvPoly {
        coefficients: vec![tmp, FieldVector::new(s_l)],
    };
    let r_poly = FvPoly {
        coefficients: vec![
            ys_fv
                .hadamard(&ar_fv.add_constant(z))
                .add(&FieldVector::new(two_times_zs.iter().map(|f| fr_to_be_bytes(*f)).collect())),
            FieldVector::new(s_r).hadamard(&ys_fv),
        ],
    };
    let t_coeffs = l_poly.inner_product(&r_poly); // [t0, t1, t2]

    let t1_rand = rng.next();
    let t2_rand = rng.next();
    let t_1 = pedersen_commit_scalar(&params.g, &params.h, t_coeffs[1], t1_rand);
    let t_2 = pedersen_commit_scalar(&params.g, &params.h, t_coeffs[2], t2_rand);

    let x = reduced_hash(&[fr_to_be_bytes(z).as_slice(), &encode_uncompressed(&t_1), &encode_uncompressed(&t_2)].concat());
    let xsquare = x * x;
    let that = t_coeffs[0] + t_coeffs[1] * x + t_coeffs[2] * xsquare;
    let tau_x = t1_rand * x + t2_rand * xsquare;
    let mu = bs_rand * x + ba_rand;

    // ---- accumulator section (prover) ------------------------------------
    // CnR / C_XR accumulate RIGHT-only (Go's nil-Left ElGamal).
    let mut cnr_r = G1Projective::ZERO;
    let mut c_xr_r = G1Projective::ZERO;
    let mut chi_bigint = Fr::ZERO;
    let mut psi_bigint = Fr::ZERO;
    let mut w_pow = Fr::ONE;
    let mut p_vec = vec![Fr::ZERO; n];
    let mut q_vec = vec![Fr::ZERO; n];
    for i in 0..m {
        cnr_r += (-phi[i].0.right).mul_bigint(w_pow.into_bigint());
        chi_bigint += chi[i].1 * w_pow;
        psi_bigint += psi[i].1 * w_pow;
        c_xr_r += (-c_xg[i].right).mul_bigint(w_pow.into_bigint());
        for j in 0..n {
            p_vec[j] += p_mat[i][j] * w_pow;
            q_vec[j] += q_mat[i][j] * w_pow;
        }
        w_pow *= w_chal;
    }
    cnr_r += cn[w.index[0]].right.mul_bigint(w_pow.into_bigint());
    let dr = c_pairs[0].right.mul_bigint(w_pow.into_bigint()) + g.mul_bigint((-chi_bigint).into_bigint());
    let gr = g.mul_bigint((w_pow - psi_bigint).into_bigint());
    p_vec[w.index[0]] += w_pow;
    q_vec[w.index[1]] += w_pow;

    let y_p = fft::convolution(&FieldVector::new(p_vec.iter().map(|f| fr_to_be_bytes(*f)).collect()), &PointVector::new(s.publickeylist.clone()));
    let y_q = fft::convolution(&FieldVector::new(q_vec.iter().map(|f| fr_to_be_bytes(*f)).collect()), &PointVector::new(s.publickeylist.clone()));

    let mut v_pow2 = Fr::ONE;
    let mut y_xr = G1Projective::ZERO;
    for i in 0..n {
        let ypoly = if i % 2 == 0 { &y_p } else { &y_q };
        let term = ypoly.0[i / 2].mul_bigint(v_pow2.into_bigint());
        y_xr += term;
        c_xr_r += term;
        if i > 0 {
            v_pow2 *= v;
        }
    }

    // ---- sigma protocol ---------------------------------------------------
    let k_sk = rng.next();
    let k_r = rng.next();
    let k_b = rng.next();
    let k_tau = rng.next();

    let a_y = gr.mul_bigint(k_sk.into_bigint());
    let a_d = g.mul_bigint(k_r.into_bigint());
    let mut a_b = g.mul_bigint(k_b.into_bigint());
    // d1 = (DR * -zs[0] + CnR_right * zs[1]) * k_sk
    let d1 = (dr.mul_bigint((-zs[0]).into_bigint()) + cnr_r.mul_bigint(zs[1].into_bigint())).mul_bigint(k_sk.into_bigint());
    a_b += d1;
    let a_x = c_xr_r.mul_bigint(k_r.into_bigint());
    let a_t = g.mul_bigint((-k_b).into_bigint()) + params.h.mul_bigint(k_tau.into_bigint());
    // A_u = HashToPoint(keccak("DERO" || roothash || scid || scid_index)) * k_sk
    let mut u_input = b"DERO".to_vec();
    u_input.extend_from_slice(&s.roothash);
    u_input.extend_from_slice(scid);
    u_input.extend_from_slice(scid_index.to_string().as_bytes());
    let a_u = crate::hash_to_point::hash_to_point(&keccak256(&u_input)).mul_bigint(k_sk.into_bigint());

    let c_chal = reduced_hash(
        &[fr_to_be_bytes(x).as_slice(), &encode_uncompressed(&a_y), &encode_uncompressed(&a_d), &encode_uncompressed(&a_b), &encode_uncompressed(&a_x), &encode_uncompressed(&a_t), &encode_uncompressed(&a_u)].concat(),
    );

    let s_sk = c_chal * w.secret_key + k_sk;
    let s_r = c_chal * w.r + k_r;
    let w_tmp = (Fr::from(w.transfer_amount as u64) * zs[0] + Fr::from(w.balance as u64) * zs[1]) * w_pow * c_chal;
    let s_b = w_tmp + k_b;
    let s_tau = tau_x * w_pow * c_chal + k_tau;

    let o = reduced_hash(&fr_to_be_bytes(c_chal));

    // ---- inner-product argument (folded basis) ---------------------------
    let ys_inv: Vec<Fr> = ys.iter().map(|y| y.inverse().expect("y invertible")).collect();
    let hs_prime: Vec<G1Projective> = params.hs.iter().zip(&ys_inv).map(|(h, yi)| h.mul_bigint(yi.into_bigint())).collect();
    let u_prime = params.h.mul_bigint(o.into_bigint());
    let base_prime = PedersenParams {
        g: params.g,
        h: u_prime,
        gsum: G1Projective::ZERO,
        gs: params.gs.clone(),
        hs: hs_prime.clone(),
    };
    let gvalues = l_poly.evaluate(x);
    let hvalues = r_poly.evaluate(x);
    let ip = innerproduct::generate(&base_prime, &G1Projective::ZERO, &gvalues, &hvalues, &fr_to_be_bytes(o));

    Proof {
        ba, bs,
        a: proof_a, b: proof_b,
        clng, crng, c_0g: c_0gv, dg: dgv, y_0g: y_0gv, gg: ggv,
        c_xg: c_xgv, y_xg: y_xgv,
        u: *u,
        f: f_fv, z_a, t_1, t_2, that, mu,
        c: c_chal, s_sk, s_r, s_b, s_tau,
        ip,
    }
}

// ---------------------------------------------------------------------------
// Serialize (matches Go Proof.Serialize byte order)
// ---------------------------------------------------------------------------

pub fn serialize(p: &Proof) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 * 33 + 8 * 33 * p.clng.len() + 33 + 32 * p.f.length() + 32 + 2 * 33 + 7 * 32 + 64 + 66 * p.ip.ls.len());
    for pt in [&p.ba, &p.bs, &p.a, &p.b] {
        out.extend_from_slice(&encode_compressed(pt));
    }
    for i in 0..p.clng.len() {
        for pt in [&p.clng[i], &p.crng[i], &p.c_0g[i], &p.dg[i], &p.y_0g[i], &p.gg[i], &p.c_xg[i], &p.y_xg[i]] {
            out.extend_from_slice(&encode_compressed(pt));
        }
    }
    out.extend_from_slice(&encode_compressed(&p.u));
    for el in &p.f.0 {
        out.extend_from_slice(el);
    }
    out.extend_from_slice(&fr_to_be_bytes(p.z_a));
    out.extend_from_slice(&encode_compressed(&p.t_1));
    out.extend_from_slice(&encode_compressed(&p.t_2));
    for s in [p.that, p.mu, p.c, p.s_sk, p.s_r, p.s_b, p.s_tau] {
        out.extend_from_slice(&fr_to_be_bytes(s));
    }
    out.extend_from_slice(&innerproduct::serialize(&p.ip));
    out
}

// ---------------------------------------------------------------------------
// Verify (mirrors proof.Verify in proof_verify.go)
// ---------------------------------------------------------------------------

pub fn verify(
    scid: &[u8; 32],
    scid_index: i32,
    s: &Statement,
    proof: &Proof,
    txid: &[u8; 32],
    extra_value: u64,
) -> bool {
    if s.c.len() != s.publickeylist.len() {
        return false;
    }
    let total_open_value = s.fees + extra_value;
    if total_open_value < s.fees || total_open_value < extra_value {
        return false;
    }
    let params = generator_params(128);
    let g = base_g();

    let statementhash = reduced_hash(txid);
    let v = reduced_hash(
        &[fr_to_be_bytes(statementhash).as_slice(), &encode_uncompressed(&proof.ba), &encode_uncompressed(&proof.bs), &encode_uncompressed(&proof.a), &encode_uncompressed(&proof.b)].concat(),
    );
    let w_chal = hashmash1(v, &[&proof.clng, &proof.crng, &proof.c_0g, &proof.dg, &proof.y_0g, &proof.gg, &proof.c_xg, &proof.y_xg]);

    let m = proof.f.length() / 2;
    let n = 1usize << m;

    // f[k][1] = f[k], f[k][0] = w - f[k]; parity check
    let mut f: Vec<[Fr; 2]> = Vec::with_capacity(2 * m);
    for k in 0..2 * m {
        let fk = proof.f.element_fr(k);
        f.push([w_chal - fk, fk]);
    }
    if w_chal != proof.f.element_fr(0) && w_chal != proof.f.element_fr(m) {
        return false;
    }

    // temp = Σ Gs[k]^f[k][1] + Hs[k]^(f[k][1]*f[k][0]) + Hs[2m]^(f0*fm) + Hs[2m+1]^(f0'*fm')
    let mut temp = G1Projective::ZERO;
    for k in 0..2 * m {
        temp += params.gs[k].mul_bigint(f[k][1].into_bigint());
        temp += params.hs[k].mul_bigint((f[k][1] * f[k][0]).into_bigint());
    }
    temp += params.hs[2 * m].mul_bigint((f[0][1] * f[m][1]).into_bigint());
    temp += params.hs[2 * m + 1].mul_bigint((f[0][0] * f[m][0]).into_bigint());

    let stored = proof.b.mul_bigint(w_chal.into_bigint()) + proof.a;
    let computed = temp + params.h.mul_bigint(proof.z_a.into_bigint());
    if stored != computed {
        return false;
    }

    let r = assemblepolynomials(&f);

    // CLnR / CRnR from r[i][0]
    let mut cln_r = G1Projective::ZERO;
    let mut crn_r = G1Projective::ZERO;
    for i in 0..n {
        cln_r += s.cln[i].mul_bigint(r[i][0].into_bigint());
        crn_r += s.crn[i].mul_bigint(r[i][0].into_bigint());
    }
    let p_fv = FieldVector::new(r.iter().map(|x| fr_to_be_bytes(x[0])).collect());
    let q_fv = FieldVector::new(r.iter().map(|x| fr_to_be_bytes(x[1])).collect());
    let c_p = fft::convolution(&p_fv, &PointVector::new(s.c.clone()));
    let c_q = fft::convolution(&q_fv, &PointVector::new(s.c.clone()));
    let y_p = fft::convolution(&p_fv, &PointVector::new(s.publickeylist.clone()));
    let y_q = fft::convolution(&q_fv, &PointVector::new(s.publickeylist.clone()));

    // C_XR / y_XR from CR[i/2][i%2], yR[i/2][i%2] with vPow
    let mut c_xr = G1Projective::ZERO;
    let mut y_xr = G1Projective::ZERO;
    let mut v_pow = Fr::ONE;
    for i in 0..n {
        let (cp, cq) = (c_p.0[i / 2], c_q.0[i / 2]);
        let (yp, yq) = (y_p.0[i / 2], y_q.0[i / 2]);
        c_xr += (if i % 2 == 0 { cp } else { cq }).mul_bigint(v_pow.into_bigint());
        y_xr += (if i % 2 == 0 { yp } else { yq }).mul_bigint(v_pow.into_bigint());
        if i > 0 {
            v_pow *= v;
        }
    }

    // wPow loop over the proof's point arrays
    let mut w_pow = Fr::ONE;
    let mut cr00 = c_p.0[0]; // CR[0][0]
    let mut yr00 = y_p.0[0]; // yR[0][0]
    let mut gr = G1Projective::ZERO;
    let mut dr = G1Projective::ZERO;
    for i in 0..m {
        let w_neg = -w_pow;
        cln_r += proof.clng[i].mul_bigint(w_neg.into_bigint());
        crn_r += proof.crng[i].mul_bigint(w_neg.into_bigint());
        cr00 += proof.c_0g[i].mul_bigint(w_neg.into_bigint());
        dr += proof.dg[i].mul_bigint(w_neg.into_bigint());
        yr00 += proof.y_0g[i].mul_bigint(w_neg.into_bigint());
        gr += proof.gg[i].mul_bigint(w_neg.into_bigint());
        c_xr += proof.c_xg[i].mul_bigint(w_neg.into_bigint());
        y_xr += proof.y_xg[i].mul_bigint(w_neg.into_bigint());
        w_pow *= w_chal;
    }
    dr += s.d.mul_bigint(w_pow.into_bigint());
    gr += g.mul_bigint(w_pow.into_bigint());
    c_xr += g.mul_bigint((Fr::from(total_open_value as u64) * w_pow).into_bigint());

    // protocol support: y, ys, k, z, zs, delta
    let y = reduced_hash(&fr_to_be_bytes(w_chal));
    let ys: Vec<Fr> = (0..128).scan(Fr::ONE, |acc, _| { let cur = *acc; *acc *= y; Some(cur) }).collect();
    let mut k = ys.iter().fold(Fr::ZERO, |acc, v| acc + *v); // Σ ys[i] (ys[0]=1 included)
    let z = reduced_hash(&fr_to_be_bytes(y));
    let zs = vec![z * z, z * z * z];
    let z_sum = (zs[0] + zs[1]) * z;
    let z_z0 = z - zs[0];
    k *= z_z0;
    let two_64 = Fr::from(u64::MAX) + Fr::ONE; // 2^64
    let zsum_pow = z_sum * two_64 - z_sum;
    k -= zsum_pow;
    let t = proof.that - k;

    let mut two_times_zs = vec![Fr::ZERO; 128];
    for i in 0..64 {
        two_times_zs[i] = zs[0] * Fr::from(1u64 << i);
        two_times_zs[64 + i] = zs[1] * Fr::from(1u64 << i);
    }

    let x = reduced_hash(&[fr_to_be_bytes(z).as_slice(), &encode_uncompressed(&proof.t_1), &encode_uncompressed(&proof.t_2)].concat());
    let xsq = x * x;
    let t_eval = proof.t_1.mul_bigint(x.into_bigint()) + proof.t_2.mul_bigint(xsq.into_bigint());

    let c_neg = -proof.c;

    // sigma support
    let a_y = gr.mul_bigint(proof.s_sk.into_bigint()) + yr00.mul_bigint(c_neg.into_bigint());
    let a_d = g.mul_bigint(proof.s_r.into_bigint()) + s.d.mul_bigint(c_neg.into_bigint());
    let zs0_neg = -zs[0];
    let left = (dr.mul_bigint(zs0_neg.into_bigint()) + crn_r.mul_bigint(zs[1].into_bigint())).mul_bigint(proof.s_sk.into_bigint());
    let mid = g.mul_bigint((Fr::from(total_open_value as u64) * w_pow).into_bigint()) + cr00;
    let right = (mid.mul_bigint(zs0_neg.into_bigint()) + cln_r.mul_bigint(zs[1].into_bigint())).mul_bigint(c_neg.into_bigint());
    let a_b = g.mul_bigint(proof.s_b.into_bigint()) + left + right;
    let a_x = y_xr.mul_bigint(proof.s_r.into_bigint()) + c_xr.mul_bigint(c_neg.into_bigint());
    let s_b_neg = -proof.s_b;
    let mut a_t = (g.mul_bigint(t.into_bigint()) - t_eval).mul_bigint((proof.c * w_pow).into_bigint());
    a_t += params.h.mul_bigint(proof.s_tau.into_bigint());
    a_t += g.mul_bigint(s_b_neg.into_bigint());

    let mut u_input = b"DERO".to_vec();
    u_input.extend_from_slice(&s.roothash);
    u_input.extend_from_slice(scid);
    u_input.extend_from_slice(scid_index.to_string().as_bytes());
    let a_u = crate::hash_to_point::hash_to_point(&keccak256(&u_input)).mul_bigint(proof.s_sk.into_bigint())
        + proof.u.mul_bigint(c_neg.into_bigint());

    // challenge consistency: c must equal reducedhash(x || A_y || ...)
    let c_check = reduced_hash(
        &[fr_to_be_bytes(x).as_slice(), &encode_uncompressed(&a_y), &encode_uncompressed(&a_d), &encode_uncompressed(&a_b), &encode_uncompressed(&a_x), &encode_uncompressed(&a_t), &encode_uncompressed(&a_u)].concat(),
    );
    if c_check != proof.c {
        return false;
    }

    // inner-product check
    let o = reduced_hash(&fr_to_be_bytes(proof.c));
    let u_x = params.h.mul_bigint(o.into_bigint());
    let ys_inv: Vec<Fr> = ys.iter().map(|yi| yi.inverse().expect("y invertible")).collect();
    let hs_prime: Vec<G1Projective> = params.hs.iter().zip(&ys_inv).map(|(h, yi)| h.mul_bigint(yi.into_bigint())).collect();
    let mut h_prime_sum = G1Projective::ZERO;
    for i in 0..128 {
        h_prime_sum += hs_prime[i].mul_bigint((ys[i] * z + two_times_zs[i]).into_bigint());
    }
    let p = proof.ba
        + proof.bs.mul_bigint(x.into_bigint())
        + params.gsum.mul_bigint((-z).into_bigint())
        + h_prime_sum
        + params.h.mul_bigint((-proof.mu).into_bigint())
        + u_x.mul_bigint(proof.that.into_bigint());

    innerproduct::verify(&proof.ip, &hs_prime, &u_x, &p, &fr_to_be_bytes(o), &params)
}

/// Nonce (Go: keccak256(u compressed)).
pub fn nonce(p: &Proof) -> [u8; 32] {
    keccak256(&encode_compressed(&p.u))
}

/// Parity (Go: f[0] == 0).
pub fn parity(p: &Proof) -> bool {
    p.f.element_fr(0) == Fr::ZERO
}

/// Debug: replay the deterministic prefix of generate_proof and return the
/// aa/ba vectors and P/Q matrices (mirrors Go OracleBPDebug).
pub fn debug_prefix(s: &Statement, w: &Witness, rand_bytes: &[u8]) -> serde_json::Value {
    use serde_json::json;
    let mut rng = RandSource(rand_bytes.to_vec());
    // consume the same draws as generate_proof: BA, sL, sR, BS
    let _ = rng.next();
    for _ in 0..256 {
        let _ = rng.next();
    }
    let _ = rng.next();
    let n = s.publickeylist.len();
    let m = (n as f64).log2() as usize;
    let aa_draws: Vec<Fr> = (0..2 * m - 2).map(|_| rng.next()).collect();
    let mut aa: Vec<Fr> = vec![Fr::ZERO; 2 * m];
    {
        let mut d = 0;
        for i in 0..2 * m {
            if i != 0 && i != m {
                aa[i] = aa_draws[d];
                d += 1;
            }
        }
    }
    let bits = witness_bits(w.index[0], w.index[1], m);
    let ba: Vec<Fr> = bits.iter().map(|b| if *b { Fr::ONE } else { Fr::ZERO }).collect();
    let a_frs: Vec<Fr> = aa;
    let b_frs: Vec<Fr> = ba;
    let pi = recursive_polynomials(&Polynomial::new(None), &a_frs[..m], &b_frs[..m]);
    let qi = recursive_polynomials(&Polynomial::new(None), &a_frs[m..], &b_frs[m..]);
    let mut p_mat: Vec<Vec<Fr>> = vec![vec![Fr::ZERO; pi.len()]; m];
    let mut q_mat: Vec<Vec<Fr>> = vec![vec![Fr::ZERO; qi.len()]; m];
    for i in 0..m {
        for (j, pj) in pi.iter().enumerate() {
            p_mat[i][j] = fr_from_be_bytes(&pj.coefficients[i]);
        }
        for (j, qj) in qi.iter().enumerate() {
            q_mat[i][j] = fr_from_be_bytes(&qj.coefficients[i]);
        }
    }
    json!({
        "aa": a_frs.iter().map(|f| fr_to_hex(*f)).collect::<Vec<_>>(),
        "ba": b_frs.iter().map(|f| fr_to_hex(*f)).collect::<Vec<_>>(),
        "p": p_mat.iter().map(|row| row.iter().map(|f| fr_to_hex(*f)).collect::<Vec<_>>()).collect::<Vec<_>>(),
        "q": q_mat.iter().map(|row| row.iter().map(|f| fr_to_hex(*f)).collect::<Vec<_>>()).collect::<Vec<_>>(),
    })
}
