// SPDX-License-Identifier: BSD-3-Clause
//
//! DERO mnemonic (recovery words) — clean-room port of the reference
//! walletapi/mnemonics algorithm.
//!
//! 24 words → 32-byte seed:
//!   - each group of 3 words maps to 4 little-endian bytes
//!   - val = w1 + L*((L-w1+w2)%L) + L²*((L-w2+w3)%L)   (L = wordlist len)
//!   - the 25th word is a crc32 checksum over the first-3-chars of the
//!     first 24 words, mod 24 (verify only — not needed for derivation)

use std::collections::HashMap;

pub const SEED_LENGTH: usize = 24;

lazy_static::lazy_static! {
    static ref ENGLISH: Vec<String> = {
        include_str!("english_words.txt")
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect()
    };
    static ref INDEX: HashMap<String, usize> = {
        let mut m = HashMap::with_capacity(1626);
        for (i, w) in ENGLISH.iter().enumerate() {
            m.insert(w.clone(), i);
        }
        m
    };
}

/// The English wordlist (1626 words).
pub fn english_words() -> &'static Vec<String> {
    &ENGLISH
}

/// Look up a word's index, or None if not in the list.
pub fn word_index(word: &str) -> Option<usize> {
    INDEX.get(word).copied()
}

/// Words → 32-byte seed (Go `Words_To_Key`, English only).
/// Accepts 24 words (no checksum) or 25 (with checksum word, verified).
pub fn words_to_key(words: &[String]) -> Result<[u8; 32], String> {
    if words.len() != SEED_LENGTH && words.len() != SEED_LENGTH + 1 {
        return Err("Invalid Seed".into());
    }
    // find indices (English only — the simnode seeds are English)
    let mut indices = Vec::with_capacity(words.len());
    for w in words {
        let idx = INDEX
            .get(w.as_str())
            .ok_or_else(|| format!("word not in English list: {w}"))?;
        indices.push(*idx as u64);
    }
    // verify checksum if 25 words
    if words.len() == SEED_LENGTH + 1 {
        let calc = checksum_index(&words[..SEED_LENGTH], 3)?;
        if words[calc as usize] != words[SEED_LENGTH] {
            return Err("Seed Checksum failed".into());
        }
    }
    let l = ENGLISH.len() as u64;
    let mut key = [0u8; 32];
    for i in 0..(SEED_LENGTH / 3) {
        let w1 = indices[i * 3];
        let w2 = indices[i * 3 + 1];
        let w3 = indices[i * 3 + 2];
        let val = w1 + l * (((l - w1) + w2) % l) + l * l * (((l - w2) + w3) % l);
        let value_32bit = val as u32; // Go: uint32(val)
        key[i * 4..i * 4 + 4].copy_from_slice(&value_32bit.to_le_bytes());
    }
    Ok(key)
}

/// crc32 over the first `prefix_len` chars of each word, mod SEED_LENGTH.
fn checksum_index(words: &[String], prefix_len: usize) -> Result<u32, String> {
    if words.len() != SEED_LENGTH {
        return Err("Words not equal to seed length".into());
    }
    let mut trimmed = String::new();
    for w in words {
        let chars: Vec<char> = w.chars().collect();
        if chars.len() > prefix_len {
            trimmed.extend(chars[..prefix_len].iter());
        } else {
            trimmed.push_str(w);
        }
    }
    let crc = crc32fast::hash(trimmed.as_bytes());
    Ok(crc % SEED_LENGTH as u32)
}

/// 32-byte seed → secret scalar (Go `crypto.GetBNRed(seed)`):
/// the seed bytes ARE the scalar — GetBNRed is just big.Int.Set (no mod).
pub fn seed_to_scalar(seed: &[u8; 32]) -> [u8; 32] {
    *seed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_sanity() {
        assert_eq!(ENGLISH.len(), 1626);
        assert_eq!(ENGLISH[0], "abbey");
        assert_eq!(ENGLISH[1625], "zoom");
    }

    #[test]
    fn simnode_wsrc_seed() {
        // the simnode's source wallet recovery words
        let words: Vec<String> = "sequence atlas unveil summon pebbles tuesday beer rudely snake rockets different fuselage woven tagged bested dented vegan hover rapid fawns obvious muppet randomly seasons randomly"
            .split_whitespace().map(|s| s.to_string()).collect();
        assert_eq!(words.len(), 25);
        let key = words_to_key(&words).expect("derive");
        eprintln!("wsrc seed: {}", hex::encode(key));
        // we cannot assert the exact value yet (need the Go oracle's output)
        // but the derivation must be deterministic
        let key2 = words_to_key(&words).unwrap();
        assert_eq!(key, key2);
    }
}
