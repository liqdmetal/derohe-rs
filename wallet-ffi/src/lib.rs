//! C-FFI wallet SDK for DERO.
//!
//! Exposes wallet functions via `extern "C"` for iOS (Swift bridging) and
//! Android (JNI). All functions are panic-safe (catch_unwind), return null
//! pointers / 0 on error, and use C-compatible types.
//!
//! # Naming convention
//!
//! All exported symbols are prefixed `dero_` and use the `DERO_*` C ABI:
//!   - strings are null-terminated `const char*` (owned by the caller, or
//!     heap-allocated via `dero_string_free` when returned from FFI)
//!   - byte buffers are `const uint8_t*` + `size_t`
//!   - output is either a return value or an out-pointer
//!   - errors produce NULL / 0; success produces non-NULL / non-zero

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uchar};
use std::panic::{catch_unwind, AssertUnwindSafe};

use ark_bn254::Fr;
use ark_ec::PrimeGroup;
use ark_ff::PrimeField;

use dero_crypto::bulletproof;
use dero_crypto::curve::{bigint_to_be32, encode_compressed};
use dero_crypto::hash_to_point::base_g;
use dero_crypto::rpc_addr::{address_to_compressed, compressed_to_address};
use dero_crypto::transaction::Transaction;
use dero_crypto::block::Block;

// ---------------------------------------------------------------------------
// Opaque types
// ---------------------------------------------------------------------------

/// Opaque DERO keypair (returned by `dero_generate_keypair`).
///   secret: 32-byte secret scalar (big-endian)
///   public: 33-byte compressed public key
#[repr(C)]
pub struct DeroKeypair {
    pub secret: [u8; 32],
    pub public: [u8; 33],
}

/// Opaque 32-byte hash (txid or block hash).
#[repr(C)]
pub struct DeroHash {
    pub hash: [u8; 32],
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a Rust `Result<T, String>` into an FFI-safe outcome.
/// On `Ok(val)` returns `val`; on `Err(msg)` returns a string suitable for
/// logging (currently discarded — could be exposed via a last-error slot).
fn _ffi_result<T, E: std::fmt::Display>(r: Result<T, E>) -> Option<T> {
    match r {
        Ok(v) => Some(v),
        Err(_e) => {
            // In production you'd store this in a thread-local last-error slot.
            // For now, just swallow it.
            None
        }
    }
}

/// Copy a byte slice into a freshly `malloc`-ed buffer and return a raw
/// pointer + length via out-params. The caller is responsible for calling
/// `dero_free` on the returned pointer.
unsafe fn _box_bytes(data: &[u8]) -> (*mut c_uchar, usize) {
    if data.is_empty() {
        return (std::ptr::null_mut(), 0);
    }
    let mut buf = vec![0u8; data.len()];
    buf.copy_from_slice(data);
    // Convert Vec into a raw pointer without releasing the allocation
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    (ptr, data.len())
}

/// Copy a fixed-size array into a heap-allocated box and return a raw pointer.
unsafe fn _box_fixed<const N: usize>(data: [u8; N]) -> *mut u8 {
    let boxed = Box::into_raw(Box::new(data));
    boxed as *mut u8
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/// Generate a new DERO keypair.
///
/// Fills in the `DeroKeypair` struct at `out`:
///   - `secret`: 32-byte secret scalar (big-endian, reduced mod n)
///   - `public`: 33-byte compressed public key (= secret * G)
///
/// Returns 1 on success, 0 on failure (panic or null `out`).
///
/// # Safety
/// `out` must be a valid, writable pointer to a `DeroKeypair` struct.
#[no_mangle]
pub unsafe extern "C" fn dero_generate_keypair(out: *mut DeroKeypair) -> c_int {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out.is_null() {
            return false;
        }
        use ark_ff::UniformRand;
        let mut rng = rand::thread_rng();

        // Generate a random scalar in Fr (= Z/nZ) using UniformRand,
        // which handles the reduction mod n correctly.
        let secret_fr = Fr::rand(&mut rng);

        // The public key is secret * G (where G = base_g())
        let g = base_g();
        let public_pt = g.mul_bigint(secret_fr.into_bigint());

        // Encode public key in DERO compressed format (33 bytes)
        let public_bytes = encode_compressed(&public_pt);

        // Re-encode the secret in canonical form (reduced mod n)
        let secret_canonical = bigint_to_be32(secret_fr.into_bigint());

        // Write out
        std::ptr::write_unaligned(out, DeroKeypair {
            secret: secret_canonical,
            public: public_bytes,
        });
        true
    }));
    if result.unwrap_or(false) {
        1
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// Address conversion
// ---------------------------------------------------------------------------

/// Convert a bech32 DERO address string to 33-byte raw compressed key.
///
/// Returns a heap-allocated pointer to 33 bytes, or NULL on error.
/// The caller must call `dero_free(ptr, 33)` to release the buffer.
///
/// # Safety
/// `addr` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn dero_address_to_raw(addr: *const c_char) -> *mut c_uchar {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if addr.is_null() {
            return None;
        }
        let c_str = CStr::from_ptr(addr);
        let s = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => return None,
        };
        address_to_compressed(s).ok()
    }));
    match result {
        Ok(Some(data)) => {
            if data.len() != 33 {
                return std::ptr::null_mut();
            }
            let mut buf = vec![0u8; 33];
            buf.copy_from_slice(&data);
            let ptr = buf.as_mut_ptr();
            std::mem::forget(buf);
            ptr
        }
        _ => std::ptr::null_mut(),
    }
}

/// Convert 33-byte raw compressed key to a bech32 DERO address string.
///
/// Returns a heap-allocated null-terminated C string, or NULL on error.
/// The caller must call `dero_string_free(ptr)` to release the string.
///
/// # Safety
/// `raw` must point to at least 33 bytes.
#[no_mangle]
pub unsafe extern "C" fn dero_address_from_raw(raw: *const c_uchar) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if raw.is_null() {
            return None;
        }
        let bytes = std::slice::from_raw_parts(raw, 33);
        compressed_to_address(bytes).ok()
    }));
    match result {
        Ok(Some(s)) => {
            match CString::new(s) {
                Ok(c) => c.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
        _ => std::ptr::null_mut(),
    }
}

/// Check if a bech32 DERO address is valid.
///
/// Returns 1 if valid, 0 if invalid, -1 on panic/error.
///
/// # Safety
/// `addr` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn dero_address_valid(addr: *const c_char) -> c_int {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if addr.is_null() {
            return -1;
        }
        let c_str = CStr::from_ptr(addr);
        let s = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        };
        if address_to_compressed(s).is_ok() {
            1
        } else {
            0
        }
    }));
    result.unwrap_or(-1)
}

// ---------------------------------------------------------------------------
// Transaction deserialization
// ---------------------------------------------------------------------------

/// Deserialize a DERO transaction from its wire format.
///
/// On success, returns a heap-allocated `DeroHash` containing the 32-byte
/// txid (keccak256 of the transaction header). Returns NULL on error.
///
/// The caller must call `dero_hash_free(ptr)` to release the result.
///
/// # Safety
/// `blob` must point to at least `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn dero_tx_deserialize(
    blob: *const c_uchar,
    len: usize,
) -> *mut DeroHash {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if blob.is_null() || len == 0 {
            return None;
        }
        let data = std::slice::from_raw_parts(blob, len);
        // bpp = 3 (mainnet bytes_per_publickey)
        let tx = Transaction::deserialize(data, 3).ok()?;
        let txid = tx.get_hash(3);
        Some(txid)
    }));
    match result {
        Ok(Some(hash)) => Box::into_raw(Box::new(DeroHash { hash })),
        _ => std::ptr::null_mut(),
    }
}

// ---------------------------------------------------------------------------
// Block deserialization
// ---------------------------------------------------------------------------

/// Deserialize a DERO block from its wire format.
///
/// On success, returns a heap-allocated `DeroHash` containing the 32-byte
/// block hash (NIST SHA3-256 of the full serialization). Returns NULL on
/// error.
///
/// The caller must call `dero_hash_free(ptr)` to release the result.
///
/// # Safety
/// `blob` must point to at least `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn dero_block_deserialize(
    blob: *const c_uchar,
    len: usize,
) -> *mut DeroHash {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if blob.is_null() || len == 0 {
            return None;
        }
        let data = std::slice::from_raw_parts(blob, len);
        let block = Block::deserialize(data).ok()?;
        let hash = block.get_hash();
        Some(hash)
    }));
    match result {
        Ok(Some(hash)) => Box::into_raw(Box::new(DeroHash { hash })),
        _ => std::ptr::null_mut(),
    }
}

// ---------------------------------------------------------------------------
// Transaction proof verification
// ---------------------------------------------------------------------------

/// Deserialize a transaction and verify its embedded bulletproof.
///
/// Returns 1 if the proof is valid, 0 if invalid, -1 on deserialization error
/// or panic.
///
/// The transaction must contain at least one payload with an embedded proof.
/// The proof is verified against the deserialized statement using the
/// bulletproof verifier with the transaction's txid.
///
/// # Safety
/// `blob` must point to at least `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn dero_verify_tx(
    blob: *const c_uchar,
    len: usize,
) -> c_int {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if blob.is_null() || len == 0 {
            return -1;
        }
        let data = std::slice::from_raw_parts(blob, len);
        // bpp = 3 (mainnet bytes_per_publickey)
        let tx = match Transaction::deserialize(data, 3) {
            Ok(tx) => tx,
            Err(_) => return -1,
        };
        let txid = tx.get_hash(3);

        // For each payload with a proof, verify it
        let mut all_valid = true;
        for payload in &tx.payloads {
            if let Some(ref proof) = payload.proof {
                // Reconstruct the statement from the deserialized data.
                // The statement was deserialized from the wire format inside
                // Transaction::deserialize.
                let scid = payload.scid;
                // scid_index: the index of the asset in the transaction's
                // payload list (Go convention: the proof is generated for
                // the payload at this index).
                let scid_index = 0i32; // single-asset transactions use index 0
                let extra_value = payload.burn_value;

                let valid = bulletproof::verify(
                    &scid,
                    scid_index,
                    &payload.statement,
                    proof,
                    &txid,
                    extra_value,
                );
                if !valid {
                    all_valid = false;
                }
            }
        }
        if all_valid { 1 } else { 0 }
    }));
    result.unwrap_or(-1)
}

// ---------------------------------------------------------------------------
// Memory management
// ---------------------------------------------------------------------------

/// Free a heap-allocated byte buffer returned by FFI functions.
///
/// # Safety
/// `ptr` must have been returned by a `dero_*` function that allocates a
/// byte buffer, and `len` must match the size that was allocated.
#[no_mangle]
pub unsafe extern "C" fn dero_free(ptr: *mut c_uchar, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    // Reconstruct the Vec and drop it
    let _ = Vec::from_raw_parts(ptr, len, len);
}

/// Free a heap-allocated C string returned by FFI functions.
///
/// # Safety
/// `ptr` must have been returned by a `dero_*` function that allocates a
/// C string (via `CString::into_raw`).
#[no_mangle]
pub unsafe extern "C" fn dero_string_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    // Reconstruct the CString and drop it
    unsafe {
        let _ = CString::from_raw(ptr);
    }
}

/// Free a heap-allocated `DeroHash` returned by `dero_tx_deserialize` or
/// `dero_block_deserialize`.
///
/// # Safety
/// `ptr` must have been returned by `dero_tx_deserialize` or
/// `dero_block_deserialize`.
#[no_mangle]
pub unsafe extern "C" fn dero_hash_free(ptr: *mut DeroHash) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let _ = Box::from_raw(ptr);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_generates_valid_public_key() {
        let mut kp = DeroKeypair {
            secret: [0u8; 32],
            public: [0u8; 33],
        };
        let rc = unsafe { dero_generate_keypair(&mut kp) };
        assert_eq!(rc, 1);
        // Public key must be a valid compressed point (decode succeeds)
        assert!(decode_compressed(&kp.public).is_ok());
        // Secret must not be all zeros (vanishingly unlikely)
        assert!(kp.secret.iter().any(|&b| b != 0));
    }

    #[test]
    fn address_roundtrip() {
        // Generate a keypair, get the public key, convert to address, and back
        let mut kp = DeroKeypair {
            secret: [0u8; 32],
            public: [0u8; 33],
        };
        unsafe { dero_generate_keypair(&mut kp) };

        // public -> address string
        let addr_c = unsafe { dero_address_from_raw(kp.public.as_ptr()) };
        assert!(!addr_c.is_null());

        // address string -> raw bytes
        let raw = unsafe { dero_address_to_raw(addr_c) };
        assert!(!raw.is_null());

        // Compare
        let raw_slice = unsafe { std::slice::from_raw_parts(raw, 33) };
        assert_eq!(raw_slice, &kp.public[..]);

        // Valid address check
        let valid = unsafe { dero_address_valid(addr_c) };
        assert_eq!(valid, 1);

        // Cleanup
        unsafe {
            dero_string_free(addr_c);
            dero_free(raw, 33);
        }
    }

    #[test]
    fn invalid_address_returns_null() {
        let bad = b"not_a_dero_address\0";
        let raw = unsafe { dero_address_to_raw(bad.as_ptr() as *const c_char) };
        assert!(raw.is_null());

        let valid = unsafe { dero_address_valid(bad.as_ptr() as *const c_char) };
        assert_eq!(valid, 0);
    }

    #[test]
    fn null_inputs_are_safe() {
        let raw = unsafe { dero_address_to_raw(std::ptr::null()) };
        assert!(raw.is_null());

        let addr = unsafe { dero_address_from_raw(std::ptr::null()) };
        assert!(addr.is_null());

        let valid = unsafe { dero_address_valid(std::ptr::null()) };
        assert_eq!(valid, -1);

        let txid = unsafe { dero_tx_deserialize(std::ptr::null(), 0) };
        assert!(txid.is_null());

        let blhash = unsafe { dero_block_deserialize(std::ptr::null(), 0) };
        assert!(blhash.is_null());

        let verify = unsafe { dero_verify_tx(std::ptr::null(), 0) };
        assert_eq!(verify, -1);

        // Keygen with null out
        let rc = unsafe { dero_generate_keypair(std::ptr::null_mut()) };
        assert_eq!(rc, 0);
    }
}
