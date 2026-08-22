//! Clean-room Rust reimplementation of derohe's consensus-critical crypto.
//!
//! Written from the DERO reference source + protocol spec, NOT copied from it
//! (derohe is under the DERO Research License; this crate is a fresh
//! implementation intended for permissive licensing). Correctness is enforced
//! by differential testing against the Go reference via `harness/difftest.py`.

pub mod bulletproof;
pub mod curve;
pub mod elgamal;
pub mod fft;
pub mod fieldvector;
pub mod hash_to_point;
pub mod innerproduct;
pub mod keccak;
pub mod pedersen;
pub mod pointvector;
pub mod polynomial;
