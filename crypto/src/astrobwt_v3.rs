// SPDX-License-Identifier: BSD-3-Clause
//
//! AstroBWTv3 — the current mainnet PoW — mirrors derohe
//! `astrobwt/astrobwtv3/pow.go` + `rc4.go` + `sa_fast.go`.
//!
//! Pipeline:
//!   key    = SHA256(input)
//!   step_3 = Salsa20(key, counter=0)  (256 bytes)
//!   step_3 = RC4(step_3, step_3)
//!   lhash  = fnv1a64(step_3)
//!   loop (tries 1..): random_switcher = prev_lhash ^ lhash ^ tries;
//!     op/pos1/pos2 from its bytes; apply one of 256 op-cases to
//!     step_3[pos1..pos2]; probabilistic lhash re-mixes (xxh64 / fnv1a /
//!     siphash) and RC4 re-streams; step_3[255] ^= step_3[pos1] ^ step_3[pos2];
//!     copy the state; break when tries > 276 or (step_3[255] >= 0xf0 &&
//!     tries > 260)
//!   data_len = (tries-4)*256 + ((step_3[253]<<8 | step_3[254]) & 0x3ff)
//!   sa = SA-IS(data[:data_len]); hash = SHA256(sa as little-endian u32)

use sha2::{Digest, Sha256};

use crate::astrobwt::sais_8_32;

pub const MAX_LENGTH: usize = 256 * 384 - 1; // 98303

// ---------------------------------------------------------------------------
// RC4 (mirrors rc4.go — Go crypto/rc4 modified)
// ---------------------------------------------------------------------------

pub struct Rc4 {
    s: [u32; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    pub fn new(key: &[u8]) -> Rc4 {
        debug_assert!(!key.is_empty() && key.len() <= 256);
        let mut c = Rc4 { s: [0; 256], i: 0, j: 0 };
        for (k, slot) in c.s.iter_mut().enumerate() {
            *slot = k as u32;
        }
        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(c.s[i] as u8).wrapping_add(key[i % key.len()]);
            c.s.swap(i, j as usize);
        }
        c
    }

    /// XOR src with the keystream into dst (in place when dst == src).
    pub fn xor_keystream(&mut self, buf: &mut [u8]) {
        if buf.is_empty() {
            return;
        }
        let mut i = self.i;
        let mut j = self.j;
        for v in buf.iter_mut() {
            i = i.wrapping_add(1);
            let x = self.s[i as usize];
            j = j.wrapping_add(x as u8);
            let y = self.s[j as usize];
            self.s[i as usize] = y;
            self.s[j as usize] = x;
            *v ^= (self.s[(x.wrapping_add(y) & 0xff) as usize]) as u8;
        }
        self.i = i;
        self.j = j;
    }
}

// ---------------------------------------------------------------------------
// small hashes
// ---------------------------------------------------------------------------

pub fn fnv1a64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

use xxhash_rust::xxh64::xxh64;

fn siphash24(k0: u64, k1: u64, data: &[u8]) -> u64 {
    use std::hash::Hasher;
    let mut h = siphasher::sip::SipHasher24::new_with_keys(k0, k1);
    h.write(data);
    h.finish()
}

// ---------------------------------------------------------------------------
// the obfuscation switch (generated)
// ---------------------------------------------------------------------------

mod ops {
    use super::*;
    include!("astrobwt_v3_ops.rs");
}

// ---------------------------------------------------------------------------
// main pipeline
// ---------------------------------------------------------------------------

/// AstroBWTv3 — the current mainnet PoW hash.
pub fn astrobwt_v3(input: &[u8]) -> [u8; 32] {
    astrobwt_v3_inner(input, None).0
}

/// Debug intermediates for the differential harness.
pub struct V3Debug {
    pub hash: [u8; 32],
    pub sha_key: [u8; 32],
    pub after_salsa: [u8; 256],
    pub after_rc4: [u8; 256],
    pub lhash: u64,
    pub prev_lhash: u64,
    pub iter1_switch: u64,
    pub iter1_op: u8,
    pub iter1_pos1: u8,
    pub iter1_pos2: u8,
    pub iter1_state: [u8; 256],
    pub iter1_lhash: u64,
    pub iter1_prev: u64,
    pub tries: u64,
    pub data_len: usize,
    pub final_state: [u8; 256],
    pub data_prefix: [u8; 64],
    pub data_prefix2: [u8; 64],
    pub data_prefix200: [u8; 64],
    pub data_full: Vec<u8>,
    pub op_log: [u8; 300],
    pub pos_log: [u32; 300],
    pub switch_log: [u64; 300],
}

pub fn astrobwt_v3_debug(input: &[u8]) -> V3Debug {
    astrobwt_v3_inner(input, Some(&mut [0u8; 0])).1.unwrap()
}

fn astrobwt_v3_inner(input: &[u8], _dbg: Option<&mut [u8]>) -> ([u8; 32], Option<V3Debug>) {
    let sha_key: [u8; 32] = Sha256::digest(input).into();

    let mut step_3 = [0u8; 256];
    {
        use salsa20::cipher::{KeyIvInit, StreamCipher};
        let mut salsa = salsa20::Salsa20::new(&sha_key.into(), &[0u8; 8].into());
        salsa.apply_keystream(&mut step_3);
    }
    let after_salsa = step_3;

    let mut rc4s = Rc4::new(&step_3);
    rc4s.xor_keystream(&mut step_3);
    let after_rc4 = step_3;

    let mut lhash = fnv1a64(&step_3);
    let mut prev_lhash = lhash;

    let mut tries: u64 = 0;
    let mut data = [0u8; MAX_LENGTH + 64];

    let mut dbg = V3Debug {
        hash: [0; 32], sha_key, after_salsa, after_rc4, lhash, prev_lhash,
        iter1_switch: 0, iter1_op: 0, iter1_pos1: 0, iter1_pos2: 0,
        iter1_state: [0; 256], iter1_lhash: 0, iter1_prev: 0,
        tries: 0, data_len: 0, final_state: [0; 256], data_prefix: [0; 64],
        data_prefix2: [0; 64], data_prefix200: [0; 64], data_full: Vec::new(),
        op_log: [0; 300], pos_log: [0; 300], switch_log: [0; 300],
    };

    loop {
        tries += 1;

        let random_switcher = prev_lhash ^ lhash ^ tries;
        let op = random_switcher as u8;
        let mut pos1 = (random_switcher >> 8) as u8 as usize;
        let mut pos2 = (random_switcher >> 16) as u8 as usize;
        if pos1 > pos2 {
            std::mem::swap(&mut pos1, &mut pos2);
        }
        if pos2 - pos1 > 32 {
            pos2 = pos1 + ((pos2 - pos1) & 0x1f);
        }

        if tries == 1 {
            dbg.iter1_switch = random_switcher;
            dbg.iter1_op = op;
            dbg.iter1_pos1 = pos1 as u8;
            dbg.iter1_pos2 = pos2 as u8;
        }

        if tries <= 300 && tries > 0 {
            dbg.op_log[(tries - 1) as usize] = op;
            dbg.pos_log[(tries - 1) as usize] = ((pos1 as u32) << 16) | pos2 as u32;
            dbg.switch_log[(tries - 1) as usize] = random_switcher;
        }

        ops::apply_op(op, &mut step_3, pos1, pos2, &mut rc4s, tries, &mut lhash, &mut prev_lhash);

        let d = step_3[pos1].wrapping_sub(step_3[pos2]);
        if d < 0x10 {
            prev_lhash = lhash.wrapping_add(prev_lhash);
            lhash = xxh64(&step_3[..pos2], 0);
        }
        if d < 0x20 {
            prev_lhash = lhash.wrapping_add(prev_lhash);
            lhash = fnv1a64(&step_3[..pos2]);
        }
        if d < 0x30 {
            prev_lhash = lhash.wrapping_add(prev_lhash);
            lhash = siphash24(tries, prev_lhash, &step_3[..pos2]);
        }
        if d <= 0x40 {
            rc4s.xor_keystream(&mut step_3);
        }

        step_3[255] ^= step_3[pos1] ^ step_3[pos2];

        let start = ((tries - 1) * 256) as usize;
        data[start..start + 256].copy_from_slice(&step_3);

        if tries > 260 + 16 || (step_3[255] >= 0xf0 && tries > 260) {
            break;
        }

        if tries == 1 {
            dbg.iter1_state = step_3;
            dbg.iter1_lhash = lhash;
            dbg.iter1_prev = prev_lhash;
        }
    }

    let data_len: usize = ((tries - 4) * 256 + ((((step_3[253] as u64) << 8) | step_3[254] as u64) & 0x3ff)) as usize;
    dbg.tries = tries;
    dbg.data_len = data_len;
    dbg.final_state = step_3;
    dbg.data_prefix[..64].copy_from_slice(&data[..64]);
    dbg.data_prefix2[..64].copy_from_slice(&data[256..320]);
    dbg.data_prefix200[..64].copy_from_slice(&data[256 * 200..256 * 200 + 64]);
    dbg.data_full = data[..data_len].to_vec();
    // SA-IS over data[:data_len]
    let mut sa = [0i32; MAX_LENGTH];
    let mut tmp = [0i32; 2 * 256];
    for v in sa[..data_len].iter_mut() {
        *v = 0;
    }
    sais_8_32(&data[..data_len], 256, &mut sa[..data_len], &mut tmp);

    // serialize sa as little-endian u32 and hash with SHA256
    let mut hasher = Sha256::new();
    let mut le = [0u8; 4];
    for &c in &sa[..data_len] {
        le = (c as u32).to_le_bytes();
        hasher.update(&le);
    }
    let out = hasher.finalize();
    let mut h = [0u8; 32];
    h.copy_from_slice(&out);
    dbg.hash = h;
    (h, Some(dbg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rc4_known_keystream() {
        // RC4 key "Key" — verified against the Go reference (astrobwtv3 rc4.go,
        // which uses the uint8(x+y) indexing quirk: differs from stock RC4
        // after the first 8 bytes)
        let mut c = Rc4::new(b"Key");
        let mut buf = [0u8; 16];
        c.xor_keystream(&mut buf);
        assert_eq!(buf, [0xeb, 0x9f, 0x77, 0x81, 0xb7, 0x34, 0xca, 0x72,
                         0xa7, 0x19, 0x4a, 0x28, 0x67, 0xb6, 0x42, 0x95]);
    }

    #[test]
    fn fnv1a64_known() {
        // fnv1a64("") = 0xcbf29ce484222325; fnv1a64("a") = 0xaf63dc4c8601ec8c
        assert_eq!(fnv1a64(b""), 0xcbf29ce484222325);
        assert_eq!(fnv1a64(b"a"), 0xaf63dc4c8601ec8c);
    }

    #[test]
    fn v3_deterministic() {
        let a = astrobwt_v3(b"hello world");
        let b = astrobwt_v3(b"hello world");
        assert_eq!(a, b);
        assert_ne!(a, astrobwt_v3(b"hello worlD"));
    }
}
