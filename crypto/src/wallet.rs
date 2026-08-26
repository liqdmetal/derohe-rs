//! Wallet-side helpers for building transactions — clean-room port of the
//! reference walletapi/cryptography helpers (shared secret, user-data
//! encryption, deterministic r).

use ark_bn254::Fr;
use ark_ec::PrimeGroup;
use ark_ff::PrimeField;

use crate::curve::{bigint_to_be32, encode_compressed};
use crate::hash_to_point::base_g;
use crate::keccak::keccak256;

/// Go `HashtoNumber`: keccak256(input) as a big-endian integer.
pub fn hashto_number(input: &[u8]) -> num_bigint::BigUint {
    num_bigint::BigUint::from_bytes_be(&keccak256(input))
}

/// Go `ReducedHash`: HashtoNumber mod the bn256 group order.
pub fn reduced_hash(input: &[u8]) -> Fr {
    let n = hashto_number(input);
    let order = curve_order();
    let r = n % &order;
    // to 32-byte big-endian, then ark Fr (which reads little-endian)
    let mut be = [0u8; 32];
    let bytes = r.to_bytes_be();
    let l = bytes.len();
    if l <= 32 {
        be[32 - l..].copy_from_slice(&bytes);
    }
    let mut le = [0u8; 32];
    for i in 0..32 {
        le[i] = be[31 - i];
    }
    Fr::from_le_bytes_mod_order(&le)
}

/// The bn256 group order (alt_bn128 scalar field order r).
pub fn curve_order() -> num_bigint::BigUint {
    num_bigint::BigUint::from_bytes_be(&{
        let mut b = [0u8; 32];
        // r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
        let hexs = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";
        for (i, c) in hexs.as_bytes().chunks(2).enumerate() {
            let hi = hexval(c[0]);
            let lo = hexval(c[1]);
            b[i] = (hi << 4) | lo;
        }
        b
    })
}

fn hexval(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => 0,
    }
}

/// Go `GenerateSharedSecret`: ECDH shared point = peer_pubkey × secret,
/// then keccak256(compressed).
pub fn generate_shared_secret(secret: &Fr, peer_publickey: &ark_bn254::G1Projective) -> [u8; 32] {
    let shared = peer_publickey.mul_bigint(secret.into_bigint());
    let compressed = encode_compressed(&shared);
    keccak256(&compressed)
}

/// Go `EncryptDecryptUserData`: XChaCha20 XOR with a zero nonce.
pub fn encrypt_decrypt_user_data(key: &[u8; 32], input: &mut [u8]) {
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    let nonce = [0u8; 24];
    let mut cipher = chacha20::XChaCha20::new(key.into(), (&nonce).into());
    cipher.apply_keystream(input);
}

/// Deterministic r (Go `rinputs` construction):
/// r = ReducedHash( (HashToPoint("DERO" ‖ roothash ‖ ring_pubkeys) × secret).compressed )
pub fn calc_r(roothash: &[u8], ring_pubkeys: &[ark_bn254::G1Projective], sender_secret: &Fr) -> Fr {
    let mut rinputs = Vec::new();
    rinputs.extend_from_slice(b"DERO");
    rinputs.extend_from_slice(roothash);
    for pk in ring_pubkeys {
        rinputs.extend_from_slice(&encode_compressed(pk));
    }
    let hp = crate::hash_to_point::hash_to_point(&keccak256(&rinputs));
    let pt = hp.mul_bigint(sender_secret.into_bigint());
    reduced_hash(&encode_compressed(&pt))
}

/// u (Go `uinput` construction):
/// u = HashToPoint("DERO" ‖ roothash ‖ SCID ‖ scid_index) × secret
pub fn calc_u(roothash: &[u8], scid: &[u8; 32], scid_index: i32, sender_secret: &Fr) -> ark_bn254::G1Projective {
    let mut uinput = Vec::new();
    uinput.extend_from_slice(b"DERO");
    uinput.extend_from_slice(roothash);
    uinput.extend_from_slice(scid);
    uinput.extend_from_slice(scid_index.to_string().as_bytes());
    let hp = crate::hash_to_point::hash_to_point(&keccak256(&uinput));
    hp.mul_bigint(sender_secret.into_bigint())
}

/// Fr → 32-byte big-endian (DERO scalar encoding).
pub fn fr_to_be32(fr: Fr) -> [u8; 32] {
    bigint_to_be32(fr.into_bigint())
}

/// G1Projective → 33-byte compressed.
pub fn point_to_compressed(p: &ark_bn254::G1Projective) -> [u8; 33] {
    encode_compressed(p)
}

/// The wallet base point G = HashToPoint("DEROG") — same as base_g().
pub fn wallet_base_g() -> ark_bn254::G1Projective {
    base_g()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reduced_hash_deterministic() {
        let a = reduced_hash(b"test input");
        let b = reduced_hash(b"test input");
        assert_eq!(fr_to_be32(a), fr_to_be32(b));
    }

    #[test]
    fn shared_secret_roundtrip() {
        // ECDH symmetry: a×B == b×A
        let a = Fr::from(12345u64);
        let b = Fr::from(67890u64);
        let g = base_g();
        let A = g.mul_bigint(a.into_bigint());
        let B = g.mul_bigint(b.into_bigint());
        let s1 = generate_shared_secret(&a, &B);
        let s2 = generate_shared_secret(&b, &A);
        assert_eq!(s1, s2);
    }

    #[test]
    fn encrypt_roundtrip() {
        let key = [7u8; 32];
        let mut data = b"hello".to_vec();
        let orig = data.clone();
        encrypt_decrypt_user_data(&key, &mut data);
        assert_ne!(data, orig);
        encrypt_decrypt_user_data(&key, &mut data);
        assert_eq!(data, orig);
    }
}
