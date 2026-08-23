//! Clean-room Rust reimplementation of derohe's consensus-critical crypto.
//!
//! Written from the DERO reference source + protocol spec, NOT copied from it
//! (derohe is under the DERO Research License; this crate is a fresh
//! implementation intended for permissive licensing). Correctness is enforced
//! by differential testing against the Go reference via `harness/difftest.py`.

pub mod astrobwt;
pub mod astrobwt_v3;
pub mod balance_serdes;
pub mod block;
pub mod bulletproof;
pub mod chain;
pub mod curve;
pub mod dvm;
pub mod elgamal;
pub mod fft;
pub mod fieldvector;
pub mod graviton;
pub mod hash_to_point;
pub mod innerproduct;
pub mod keccak;
pub mod pedersen;
pub mod pointvector;
pub mod polynomial;
pub mod rpc_args;
pub mod statement;
pub mod transaction;
pub mod rpc_addr;
pub mod sc;

/// SHA-256 (used by the DVM sha256 builtin).
pub fn sha2_256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h);
    out
}

/// NIST SHA3-256 (used by the DVM sha3256 builtin).
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let h = Sha3_256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h);
    out
}
