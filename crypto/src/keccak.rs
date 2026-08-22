//! Keccak wrappers matching derohe's `cryptography/crypto/keccak.go`.
//!
//! derohe uses *legacy* Keccak (original padding 0x01), NOT NIST SHA3-256
//! (padding 0x06). tiny-keccak's `Keccak::v256`/`v512` are the correct variants.

use tiny_keccak::{Hasher, Keccak};

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut h = Keccak::v256();
    h.update(data);
    h.finalize(&mut out);
    out
}

/// derohe quirk: Go's `Keccak512` returns `Hash` = `[32]byte` and copies only
/// the first 32 bytes of the 64-byte digest (keccak.go:33-41). Replicated
/// exactly: first half of the keccak-512 output.
pub fn keccak512(data: &[u8]) -> [u8; 32] {
    let mut full = [0u8; 64];
    let mut h = Keccak::v512();
    h.update(data);
    h.finalize(&mut full);
    let mut out = [0u8; 32];
    out.copy_from_slice(&full[..32]);
    out
}

/// Mirrors derohe's `Keccak256_64`: first 8 bytes of keccak256, big-endian.
pub fn keccak256_64(data: &[u8]) -> u64 {
    let h = keccak256(data);
    u64::from_be_bytes(h[..8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;

    #[test]
    fn keccak256_empty() {
        // Known Keccak-256(empty) = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        let h = keccak256(b"");
        let expect = <[u8; 32]>::from_hex(
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )
        .unwrap();
        assert_eq!(h, expect);
    }
}
