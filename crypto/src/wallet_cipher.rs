// SPDX-License-Identifier: BSD-3-Clause
//
//! Wallet at-rest encryption — clean-room port of the reference's
//! walletapi/cipher.go: XChaCha20-Poly1305 AEAD (chacha20poly1305), the
//! 12-byte nonce appended to the ciphertext. The password-derived key is
//! the 32-byte keccak256(password) — the reference's master_password.

use crate::keccak::keccak256;

/// Encrypt data with a password: key = keccak256(password), XChaCha20-
/// Poly1305 AEAD, 12-byte nonce appended to the ciphertext.
pub fn encrypt_with_password(password: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::XChaCha20Poly1305;
    let key = keccak256(password);
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|e| format!("cipher: {e}"))?;
    // 24-byte XChaCha nonce (random)
    let mut nonce = [0u8; 24];
    getrandom::getrandom(&mut nonce).map_err(|e| format!("rng: {e}"))?;
    let ct = cipher
        .encrypt(
            &nonce.into(),
            Payload {
                msg: data,
                aad: b"",
            },
        )
        .map_err(|e| format!("encrypt: {e}"))?;
    let mut out = ct;
    out.extend_from_slice(&nonce);
    Ok(out)
}

/// Decrypt data encrypted by `encrypt_with_password`.
pub fn decrypt_with_password(password: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::XChaCha20Poly1305;
    if data.len() < 24 + 16 {
        return Err("data too short".into());
    }
    let key = keccak256(password);
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|e| format!("cipher: {e}"))?;
    let (ct, nonce) = data.split_at(data.len() - 24);
    let pt = cipher
        .decrypt(nonce.into(), Payload { msg: ct, aad: b"" })
        .map_err(|e| format!("decrypt: {e}"))?;
    Ok(pt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let pw = b"hunter2";
        let data = b"the wallet seed words";
        let enc = encrypt_with_password(pw, data).unwrap();
        // nonce is appended
        assert_eq!(enc.len(), data.len() + 24 + 16);
        let dec = decrypt_with_password(pw, &enc).unwrap();
        assert_eq!(dec, data);
        // wrong password fails
        assert!(decrypt_with_password(b"wrong", &enc).is_err());
    }
}
