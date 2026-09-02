// SPDX-License-Identifier: BSD-3-Clause
//
// Generated from the Go reference astrobwt/astrobwtv3/pow.go — do not edit.

// The op-switch body: applied to s[pos1..pos2] (Go: step_3).

// Tail lines (lhash/rc4 updates) run in place after the byte ops.

#[inline]

pub fn apply_op(op: u8, s: &mut [u8; 256], pos1: usize, pos2: usize,
                rc4s: &mut Rc4, _tries: u64, lhash_out: &mut u64, prev_out: &mut u64) {
    // rebind to locals so the generated bodies can use them directly
    let (mut lhash, mut prev_lhash) = (*lhash_out, *prev_out);
    match op {
        0 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].count_ones() as u8;
                s[i] = s[i].rotate_left(5);
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] = s[i].rotate_left(s[i] as u32);
                let t = s[pos1].reverse_bits();
                    s[pos1] = s[pos2].reverse_bits();
                    s[pos2] = t;
            }
        }
        1 => {
            for i in pos1..pos2 {
                s[i] <<= s[i] & 3;
                s[i] = s[i].rotate_left(1);
                s[i] &= s[pos2];
                s[i] = s[i].wrapping_add(s[i]);
            }
        }
        2 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].count_ones() as u8;
                s[i] = s[i].reverse_bits();
                s[i] <<= s[i] & 3;
                s[i] ^= s[i].count_ones() as u8;
            }
        }
        3 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] = s[i].rotate_left(3);
                s[i] ^= s[pos2];
                s[i] = s[i].rotate_left(1);
            }
        }
        4 => {
            for i in pos1..pos2 {
                s[i] = !s[i];
                s[i] >>= s[i] & 3;
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
            }
        }
        5 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].count_ones() as u8;
                s[i] ^= s[pos2];
                s[i] <<= s[i] & 3;
                s[i] >>= s[i] & 3;
            }
        }
        6 => {
            for i in pos1..pos2 {
                s[i] <<= s[i] & 3;
                s[i] = s[i].rotate_left(3);
                s[i] = !s[i];
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
            }
        }
        7 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_add(s[i]);
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] ^= s[i].count_ones() as u8;
                s[i] = !s[i];
            }
        }
        8 => {
            for i in pos1..pos2 {
                s[i] = !s[i];
                s[i] = s[i].rotate_left(5);
                s[i] = s[i].rotate_left(5);
                s[i] <<= s[i] & 3;
            }
        }
        9 => {
            for i in pos1..pos2 {
                s[i] ^= s[pos2];
                s[i] ^= s[i].rotate_left(4);
                s[i] >>= s[i] & 3;
                s[i] ^= s[i].rotate_left(2);
            }
        }
        10 => {
            for i in pos1..pos2 {
                s[i] = !s[i];
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] = s[i].rotate_left(3);
                s[i] = s[i].wrapping_mul(s[i]);
            }
        }
        11 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(1);
                s[i] = s[i].rotate_left(5);
                s[i] &= s[pos2];
                s[i] = s[i].rotate_left(s[i] as u32);
            }
        }
        12 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].rotate_left(2);
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] ^= s[i].rotate_left(2);
                s[i] = !s[i];
            }
        }
        13 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(1);
                s[i] ^= s[pos2];
                s[i] >>= s[i] & 3;
                s[i] = s[i].rotate_left(5);
            }
        }
        14 => {
            for i in pos1..pos2 {
                s[i] >>= s[i] & 3;
                s[i] <<= s[i] & 3;
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] <<= s[i] & 3;
            }
        }
        15 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].rotate_left(2);
                s[i] <<= s[i] & 3;
                s[i] &= s[pos2];
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
            }
        }
        16 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].rotate_left(4);
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] = s[i].rotate_left(1);
                s[i] = !s[i];
            }
        }
        17 => {
            for i in pos1..pos2 {
                s[i] ^= s[pos2];
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] = s[i].rotate_left(5);
                s[i] = !s[i];
            }
        }
        18 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].rotate_left(4);
                s[i] = s[i].rotate_left(3);
                s[i] = s[i].rotate_left(1);
                s[i] = s[i].rotate_left(5);
            }
        }
        19 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
                s[i] = s[i].rotate_left(5);
                s[i] <<= s[i] & 3;
                s[i] = s[i].wrapping_add(s[i]);
            }
        }
        20 => {
            for i in pos1..pos2 {
                s[i] &= s[pos2];
                s[i] ^= s[pos2];
                s[i] = s[i].reverse_bits();
                s[i] ^= s[i].rotate_left(2);
            }
        }
        21 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(1);
                s[i] ^= s[pos2];
                s[i] = s[i].wrapping_add(s[i]);
                s[i] &= s[pos2];
            }
        }
        22 => {
            for i in pos1..pos2 {
                s[i] <<= s[i] & 3;
                s[i] = s[i].reverse_bits();
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] = s[i].rotate_left(1);
            }
        }
        23 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(3);
                s[i] = s[i].rotate_left(1);
                s[i] ^= s[i].count_ones() as u8;
                s[i] &= s[pos2];
            }
        }
        24 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_add(s[i]);
                s[i] >>= s[i] & 3;
                s[i] ^= s[i].rotate_left(4);
                s[i] = s[i].rotate_left(5);
            }
        }
        25 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].count_ones() as u8;
                s[i] = s[i].rotate_left(3);
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
            }
        }
        26 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] ^= s[i].count_ones() as u8;
                s[i] = s[i].wrapping_add(s[i]);
                s[i] = s[i].reverse_bits();
            }
        }
        27 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(5);
                s[i] &= s[pos2];
                s[i] ^= s[i].rotate_left(4);
                s[i] = s[i].rotate_left(5);
            }
        }
        28 => {
            for i in pos1..pos2 {
                s[i] <<= s[i] & 3;
                s[i] = s[i].wrapping_add(s[i]);
                s[i] = s[i].wrapping_add(s[i]);
                s[i] = s[i].rotate_left(5);
            }
        }
        29 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] ^= s[pos2];
                s[i] >>= s[i] & 3;
                s[i] = s[i].wrapping_add(s[i]);
            }
        }
        30 => {
            for i in pos1..pos2 {
                s[i] &= s[pos2];
                s[i] ^= s[i].rotate_left(4);
                s[i] = s[i].rotate_left(5);
                s[i] <<= s[i] & 3;
            }
        }
        31 => {
            for i in pos1..pos2 {
                s[i] = !s[i];
                s[i] ^= s[i].rotate_left(2);
                s[i] <<= s[i] & 3;
                s[i] = s[i].wrapping_mul(s[i]);
            }
        }
        32 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].rotate_left(2);
                s[i] = s[i].reverse_bits();
                s[i] = s[i].rotate_left(3);
                s[i] ^= s[i].rotate_left(2);
            }
        }
        33 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] ^= s[i].rotate_left(4);
                s[i] = s[i].reverse_bits();
                s[i] = s[i].wrapping_mul(s[i]);
            }
        }
        34 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
                s[i] <<= s[i] & 3;
                s[i] <<= s[i] & 3;
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
            }
        }
        35 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_add(s[i]);
                s[i] = !s[i];
                s[i] = s[i].rotate_left(1);
                s[i] ^= s[pos2];
            }
        }
        36 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].count_ones() as u8;
                s[i] = s[i].rotate_left(1);
                s[i] ^= s[i].rotate_left(2);
                s[i] = s[i].rotate_left(1);
            }
        }
        37 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] >>= s[i] & 3;
                s[i] >>= s[i] & 3;
                s[i] = s[i].wrapping_mul(s[i]);
            }
        }
        38 => {
            for i in pos1..pos2 {
                s[i] >>= s[i] & 3;
                s[i] = s[i].rotate_left(3);
                s[i] ^= s[i].count_ones() as u8;
                s[i] = s[i].rotate_left(s[i] as u32);
            }
        }
        39 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].rotate_left(2);
                s[i] ^= s[pos2];
                s[i] >>= s[i] & 3;
                s[i] &= s[pos2];
            }
        }
        40 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] ^= s[pos2];
                s[i] ^= s[i].count_ones() as u8;
                s[i] ^= s[pos2];
            }
        }
        41 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(5);
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
                s[i] = s[i].rotate_left(3);
                s[i] ^= s[i].rotate_left(4);
            }
        }
        42 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(1);
                s[i] = s[i].rotate_left(3);
                s[i] ^= s[i].rotate_left(2);
                s[i] = s[i].rotate_left(s[i] as u32);
            }
        }
        43 => {
            for i in pos1..pos2 {
                s[i] &= s[pos2];
                s[i] = s[i].wrapping_add(s[i]);
                s[i] &= s[pos2];
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
            }
        }
        44 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].count_ones() as u8;
                s[i] ^= s[i].count_ones() as u8;
                s[i] = s[i].rotate_left(3);
                s[i] = s[i].rotate_left(s[i] as u32);
            }
        }
        45 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(5);
                s[i] = s[i].rotate_left(5);
                s[i] &= s[pos2];
                s[i] ^= s[i].count_ones() as u8;
            }
        }
        46 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].count_ones() as u8;
                s[i] = s[i].wrapping_add(s[i]);
                s[i] = s[i].rotate_left(5);
                s[i] ^= s[i].rotate_left(4);
            }
        }
        47 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(5);
                s[i] &= s[pos2];
                s[i] = s[i].rotate_left(5);
                s[i] <<= s[i] & 3;
            }
        }
        48 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] = !s[i];
                s[i] = !s[i];
                s[i] = s[i].rotate_left(5);
            }
        }
        49 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].count_ones() as u8;
                s[i] = s[i].wrapping_add(s[i]);
                s[i] = s[i].reverse_bits();
                s[i] ^= s[i].rotate_left(4);
            }
        }
        50 => {
            for i in pos1..pos2 {
                s[i] = s[i].reverse_bits();
                s[i] = s[i].rotate_left(3);
                s[i] = s[i].wrapping_add(s[i]);
                s[i] = s[i].rotate_left(1);
            }
        }
        51 => {
            for i in pos1..pos2 {
                s[i] ^= s[pos2];
                s[i] ^= s[i].rotate_left(4);
                s[i] ^= s[i].rotate_left(4);
                s[i] = s[i].rotate_left(5);
            }
        }
        52 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] >>= s[i] & 3;
                s[i] = !s[i];
                s[i] ^= s[i].count_ones() as u8;
            }
        }
        53 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_add(s[i]);
                s[i] ^= s[i].count_ones() as u8;
                s[i] ^= s[i].rotate_left(4);
                s[i] ^= s[i].rotate_left(4);
            }
        }
        54 => {
            for i in pos1..pos2 {
                s[i] = s[i].reverse_bits();
                s[i] ^= s[pos2];
                s[i] = !s[i];
                s[i] = !s[i];
            }
        }
        55 => {
            for i in pos1..pos2 {
                s[i] = s[i].reverse_bits();
                s[i] ^= s[i].rotate_left(4);
                s[i] ^= s[i].rotate_left(4);
                s[i] = s[i].rotate_left(1);
            }
        }
        56 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].rotate_left(2);
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] = !s[i];
                s[i] = s[i].rotate_left(1);
            }
        }
        57 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] = s[i].rotate_left(5);
                s[i] = s[i].rotate_left(3);
                s[i] = s[i].reverse_bits();
            }
        }
        58 => {
            for i in pos1..pos2 {
                s[i] = s[i].reverse_bits();
                s[i] ^= s[i].rotate_left(2);
                s[i] &= s[pos2];
                s[i] = s[i].wrapping_add(s[i]);
            }
        }
        59 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(1);
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] = !s[i];
            }
        }
        60 => {
            for i in pos1..pos2 {
                s[i] ^= s[pos2];
                s[i] = !s[i];
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] = s[i].rotate_left(3);
            }
        }
        61 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(5);
                s[i] <<= s[i] & 3;
                s[i] = s[i].rotate_left(3);
                s[i] = s[i].rotate_left(5);
            }
        }
        62 => {
            for i in pos1..pos2 {
                s[i] &= s[pos2];
                s[i] = !s[i];
                s[i] ^= s[i].rotate_left(2);
                s[i] = s[i].wrapping_add(s[i]);
            }
        }
        63 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(5);
                s[i] ^= s[i].count_ones() as u8;
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
                s[i] = s[i].wrapping_add(s[i]);
            }
        }
        64 => {
            for i in pos1..pos2 {
                s[i] ^= s[pos2];
                s[i] = s[i].reverse_bits();
                s[i] ^= s[i].rotate_left(4);
                s[i] = s[i].wrapping_mul(s[i]);
            }
        }
        65 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(5);
                s[i] = s[i].rotate_left(3);
                s[i] ^= s[i].rotate_left(2);
                s[i] = s[i].wrapping_mul(s[i]);
            }
        }
        66 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].rotate_left(2);
                s[i] = s[i].reverse_bits();
                s[i] ^= s[i].rotate_left(4);
                s[i] = s[i].rotate_left(1);
            }
        }
        67 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(1);
                s[i] ^= s[i].count_ones() as u8;
                s[i] ^= s[i].rotate_left(2);
                s[i] = s[i].rotate_left(5);
            }
        }
        68 => {
            for i in pos1..pos2 {
                s[i] &= s[pos2];
                s[i] = !s[i];
                s[i] ^= s[i].rotate_left(4);
                s[i] ^= s[pos2];
            }
        }
        69 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_add(s[i]);
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] = s[i].reverse_bits();
                s[i] >>= s[i] & 3;
            }
        }
        70 => {
            for i in pos1..pos2 {
                s[i] ^= s[pos2];
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] >>= s[i] & 3;
                s[i] ^= s[i].rotate_left(4);
            }
        }
        71 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(5);
                s[i] = !s[i];
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] <<= s[i] & 3;
            }
        }
        72 => {
            for i in pos1..pos2 {
                s[i] = s[i].reverse_bits();
                s[i] ^= s[i].count_ones() as u8;
                s[i] ^= s[pos2];
                s[i] <<= s[i] & 3;
            }
        }
        73 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].count_ones() as u8;
                s[i] = s[i].reverse_bits();
                s[i] = s[i].rotate_left(5);
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
            }
        }
        74 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] = s[i].rotate_left(3);
                s[i] = s[i].reverse_bits();
                s[i] &= s[pos2];
            }
        }
        75 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] ^= s[i].count_ones() as u8;
                s[i] &= s[pos2];
                s[i] ^= s[i].rotate_left(4);
            }
        }
        76 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] ^= s[i].rotate_left(2);
                s[i] = s[i].rotate_left(5);
                s[i] >>= s[i] & 3;
            }
        }
        77 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(3);
                s[i] = s[i].wrapping_add(s[i]);
                s[i] <<= s[i] & 3;
                s[i] ^= s[i].count_ones() as u8;
            }
        }
        78 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] = s[i].reverse_bits();
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
            }
        }
        79 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].rotate_left(4);
                s[i] ^= s[i].rotate_left(2);
                s[i] = s[i].wrapping_add(s[i]);
                s[i] = s[i].wrapping_mul(s[i]);
            }
        }
        80 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] <<= s[i] & 3;
                s[i] = s[i].wrapping_add(s[i]);
                s[i] &= s[pos2];
            }
        }
        81 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].rotate_left(4);
                s[i] <<= s[i] & 3;
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] ^= s[i].count_ones() as u8;
            }
        }
        82 => {
            for i in pos1..pos2 {
                s[i] ^= s[pos2];
                s[i] = !s[i];
                s[i] = !s[i];
                s[i] >>= s[i] & 3;
            }
        }
        83 => {
            for i in pos1..pos2 {
                s[i] <<= s[i] & 3;
                s[i] = s[i].reverse_bits();
                s[i] = s[i].rotate_left(3);
                s[i] = s[i].reverse_bits();
            }
        }
        84 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
                s[i] = s[i].rotate_left(1);
                s[i] <<= s[i] & 3;
                s[i] = s[i].wrapping_add(s[i]);
            }
        }
        85 => {
            for i in pos1..pos2 {
                s[i] >>= s[i] & 3;
                s[i] ^= s[pos2];
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] <<= s[i] & 3;
            }
        }
        86 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].rotate_left(4);
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] ^= s[i].rotate_left(4);
                s[i] = !s[i];
            }
        }
        87 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_add(s[i]);
                s[i] = s[i].rotate_left(3);
                s[i] ^= s[i].rotate_left(4);
                s[i] = s[i].wrapping_add(s[i]);
            }
        }
        88 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].rotate_left(2);
                s[i] = s[i].rotate_left(1);
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] = !s[i];
            }
        }
        89 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_add(s[i]);
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] = !s[i];
                s[i] ^= s[i].rotate_left(2);
            }
        }
        90 => {
            for i in pos1..pos2 {
                s[i] = s[i].reverse_bits();
                s[i] = s[i].rotate_left(5);
                s[i] = s[i].rotate_left(1);
                s[i] >>= s[i] & 3;
            }
        }
        91 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].count_ones() as u8;
                s[i] &= s[pos2];
                s[i] ^= s[i].rotate_left(4);
                s[i] = s[i].reverse_bits();
            }
        }
        92 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].count_ones() as u8;
                s[i] = !s[i];
                s[i] ^= s[i].count_ones() as u8;
                s[i] &= s[pos2];
            }
        }
        93 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].rotate_left(2);
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] &= s[pos2];
                s[i] = s[i].wrapping_add(s[i]);
            }
        }
        94 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(1);
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] &= s[pos2];
                s[i] <<= s[i] & 3;
            }
        }
        95 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(1);
                s[i] = !s[i];
                s[i] = s[i].rotate_left(5);
                s[i] = s[i].rotate_left(5);
            }
        }
        96 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].rotate_left(2);
                s[i] ^= s[i].rotate_left(2);
                s[i] ^= s[i].count_ones() as u8;
                s[i] = s[i].rotate_left(1);
            }
        }
        97 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(1);
                s[i] <<= s[i] & 3;
                s[i] ^= s[i].count_ones() as u8;
                s[i] >>= s[i] & 3;
            }
        }
        98 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].rotate_left(4);
                s[i] <<= s[i] & 3;
                s[i] >>= s[i] & 3;
                s[i] ^= s[i].rotate_left(4);
            }
        }
        99 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].rotate_left(4);
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
                s[i] = s[i].reverse_bits();
                s[i] >>= s[i] & 3;
            }
        }
        100 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] <<= s[i] & 3;
                s[i] = s[i].reverse_bits();
                s[i] ^= s[i].count_ones() as u8;
            }
        }
        101 => {
            for i in pos1..pos2 {
                s[i] >>= s[i] & 3;
                s[i] ^= s[i].count_ones() as u8;
                s[i] >>= s[i] & 3;
                s[i] = !s[i];
            }
        }
        102 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(3);
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
                s[i] = s[i].wrapping_add(s[i]);
                s[i] = s[i].rotate_left(3);
            }
        }
        103 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(1);
                s[i] = s[i].reverse_bits();
                s[i] ^= s[pos2];
                s[i] = s[i].rotate_left(s[i] as u32);
            }
        }
        104 => {
            for i in pos1..pos2 {
                s[i] = s[i].reverse_bits();
                s[i] ^= s[i].count_ones() as u8;
                s[i] = s[i].rotate_left(5);
                s[i] = s[i].wrapping_add(s[i]);
            }
        }
        105 => {
            for i in pos1..pos2 {
                s[i] <<= s[i] & 3;
                s[i] = s[i].rotate_left(3);
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] ^= s[i].rotate_left(2);
            }
        }
        106 => {
            for i in pos1..pos2 {
                s[i] = s[i].reverse_bits();
                s[i] ^= s[i].rotate_left(4);
                s[i] = s[i].rotate_left(1);
                s[i] = s[i].wrapping_mul(s[i]);
            }
        }
        107 => {
            for i in pos1..pos2 {
                s[i] >>= s[i] & 3;
                s[i] ^= s[i].rotate_left(2);
                s[i] = s[i].rotate_left(5);
                s[i] = s[i].rotate_left(1);
            }
        }
        108 => {
            for i in pos1..pos2 {
                s[i] ^= s[pos2];
                s[i] = !s[i];
                s[i] &= s[pos2];
                s[i] ^= s[i].rotate_left(2);
            }
        }
        109 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] ^= s[pos2];
                s[i] ^= s[i].rotate_left(2);
            }
        }
        110 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_add(s[i]);
                s[i] ^= s[i].rotate_left(2);
                s[i] ^= s[i].rotate_left(2);
                s[i] >>= s[i] & 3;
            }
        }
        111 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] = s[i].reverse_bits();
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] >>= s[i] & 3;
            }
        }
        112 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(3);
                s[i] = !s[i];
                s[i] = s[i].rotate_left(5);
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
            }
        }
        113 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(5);
                s[i] = s[i].rotate_left(1);
                s[i] ^= s[i].count_ones() as u8;
                s[i] = !s[i];
            }
        }
        114 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(1);
                s[i] = s[i].reverse_bits();
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] = !s[i];
            }
        }
        115 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] = s[i].rotate_left(5);
                s[i] &= s[pos2];
                s[i] = s[i].rotate_left(3);
            }
        }
        116 => {
            for i in pos1..pos2 {
                s[i] &= s[pos2];
                s[i] ^= s[pos2];
                s[i] ^= s[i].count_ones() as u8;
                s[i] <<= s[i] & 3;
            }
        }
        117 => {
            for i in pos1..pos2 {
                s[i] <<= s[i] & 3;
                s[i] = s[i].rotate_left(3);
                s[i] <<= s[i] & 3;
                s[i] &= s[pos2];
            }
        }
        118 => {
            for i in pos1..pos2 {
                s[i] >>= s[i] & 3;
                s[i] = s[i].wrapping_add(s[i]);
                s[i] <<= s[i] & 3;
                s[i] = s[i].rotate_left(5);
            }
        }
        119 => {
            for i in pos1..pos2 {
                s[i] = s[i].reverse_bits();
                s[i] ^= s[i].rotate_left(2);
                s[i] = !s[i];
                s[i] ^= s[pos2];
            }
        }
        120 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].rotate_left(2);
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] ^= s[pos2];
                s[i] = s[i].reverse_bits();
            }
        }
        121 => {
            for i in pos1..pos2 {
                s[i] >>= s[i] & 3;
                s[i] = s[i].wrapping_add(s[i]);
                s[i] ^= s[i].count_ones() as u8;
                s[i] = s[i].wrapping_mul(s[i]);
            }
        }
        122 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].rotate_left(4);
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] = s[i].rotate_left(5);
                s[i] ^= s[i].rotate_left(2);
            }
        }
        123 => {
            for i in pos1..pos2 {
                s[i] &= s[pos2];
                s[i] = !s[i];
                s[i] = s[i].rotate_left(3);
                s[i] = s[i].rotate_left(3);
            }
        }
        124 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].rotate_left(2);
                s[i] ^= s[i].rotate_left(2);
                s[i] ^= s[pos2];
                s[i] = !s[i];
            }
        }
        125 => {
            for i in pos1..pos2 {
                s[i] = s[i].reverse_bits();
                s[i] ^= s[i].rotate_left(2);
                s[i] = s[i].wrapping_add(s[i]);
                s[i] >>= s[i] & 3;
            }
        }
        126 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(3);
                s[i] = s[i].rotate_left(1);
                s[i] = s[i].rotate_left(5);
                s[i] = s[i].reverse_bits();
            }
        }
        127 => {
            for i in pos1..pos2 {
                s[i] <<= s[i] & 3;
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] &= s[pos2];
                s[i] ^= s[pos2];
            }
        }
        128 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] ^= s[i].rotate_left(2);
                s[i] ^= s[i].rotate_left(2);
                s[i] = s[i].rotate_left(5);
            }
        }
        129 => {
            for i in pos1..pos2 {
                s[i] = !s[i];
                s[i] ^= s[i].count_ones() as u8;
                s[i] ^= s[i].count_ones() as u8;
                s[i] >>= s[i] & 3;
            }
        }
        130 => {
            for i in pos1..pos2 {
                s[i] >>= s[i] & 3;
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] = s[i].rotate_left(1);
                s[i] ^= s[i].rotate_left(4);
            }
        }
        131 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
                s[i] = s[i].rotate_left(1);
                s[i] ^= s[i].count_ones() as u8;
                s[i] = s[i].wrapping_mul(s[i]);
            }
        }
        132 => {
            for i in pos1..pos2 {
                s[i] &= s[pos2];
                s[i] = s[i].reverse_bits();
                s[i] = s[i].rotate_left(5);
                s[i] ^= s[i].rotate_left(2);
            }
        }
        133 => {
            for i in pos1..pos2 {
                s[i] ^= s[pos2];
                s[i] = s[i].rotate_left(5);
                s[i] ^= s[i].rotate_left(2);
                s[i] <<= s[i] & 3;
            }
        }
        134 => {
            for i in pos1..pos2 {
                s[i] = !s[i];
                s[i] ^= s[i].rotate_left(4);
                s[i] = s[i].rotate_left(1);
                s[i] &= s[pos2];
            }
        }
        135 => {
            for i in pos1..pos2 {
                s[i] >>= s[i] & 3;
                s[i] ^= s[i].rotate_left(2);
                s[i] = s[i].wrapping_add(s[i]);
                s[i] = s[i].reverse_bits();
            }
        }
        136 => {
            for i in pos1..pos2 {
                s[i] >>= s[i] & 3;
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
                s[i] ^= s[pos2];
                s[i] = s[i].rotate_left(5);
            }
        }
        137 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(5);
                s[i] >>= s[i] & 3;
                s[i] = s[i].reverse_bits();
                s[i] = s[i].rotate_left(s[i] as u32);
            }
        }
        138 => {
            for i in pos1..pos2 {
                s[i] ^= s[pos2];
                s[i] ^= s[pos2];
                s[i] = s[i].wrapping_add(s[i]);
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
            }
        }
        139 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(5);
                s[i] = s[i].rotate_left(3);
                s[i] ^= s[i].rotate_left(2);
                s[i] = s[i].rotate_left(3);
            }
        }
        140 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(1);
                s[i] ^= s[i].rotate_left(2);
                s[i] ^= s[pos2];
                s[i] = s[i].rotate_left(5);
            }
        }
        141 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(1);
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
                s[i] ^= s[i].count_ones() as u8;
                s[i] = s[i].wrapping_add(s[i]);
            }
        }
        142 => {
            for i in pos1..pos2 {
                s[i] &= s[pos2];
                s[i] = s[i].rotate_left(5);
                s[i] = s[i].reverse_bits();
                s[i] ^= s[i].rotate_left(2);
            }
        }
        143 => {
            for i in pos1..pos2 {
                s[i] &= s[pos2];
                s[i] = s[i].rotate_left(3);
                s[i] >>= s[i] & 3;
                s[i] <<= s[i] & 3;
            }
        }
        144 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] <<= s[i] & 3;
                s[i] = !s[i];
                s[i] = s[i].rotate_left(s[i] as u32);
            }
        }
        145 => {
            for i in pos1..pos2 {
                s[i] = s[i].reverse_bits();
                s[i] ^= s[i].rotate_left(4);
                s[i] ^= s[i].rotate_left(2);
                s[i] ^= s[i].rotate_left(4);
            }
        }
        146 => {
            for i in pos1..pos2 {
                s[i] &= s[pos2];
                s[i] <<= s[i] & 3;
                s[i] &= s[pos2];
                s[i] ^= s[i].count_ones() as u8;
            }
        }
        147 => {
            for i in pos1..pos2 {
                s[i] = !s[i];
                s[i] <<= s[i] & 3;
                s[i] ^= s[i].rotate_left(4);
                s[i] = s[i].wrapping_mul(s[i]);
            }
        }
        148 => {
            for i in pos1..pos2 {
                s[i] &= s[pos2];
                s[i] = s[i].rotate_left(5);
                s[i] <<= s[i] & 3;
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
            }
        }
        149 => {
            for i in pos1..pos2 {
                s[i] ^= s[pos2];
                s[i] = s[i].reverse_bits();
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
                s[i] = s[i].wrapping_add(s[i]);
            }
        }
        150 => {
            for i in pos1..pos2 {
                s[i] <<= s[i] & 3;
                s[i] <<= s[i] & 3;
                s[i] <<= s[i] & 3;
                s[i] &= s[pos2];
            }
        }
        151 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_add(s[i]);
                s[i] <<= s[i] & 3;
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] <<= s[i] & 3;
            }
        }
        152 => {
            for i in pos1..pos2 {
                s[i] >>= s[i] & 3;
                s[i] = !s[i];
                s[i] <<= s[i] & 3;
                s[i] ^= s[i].rotate_left(2);
            }
        }
        153 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(1);
                s[i] = s[i].rotate_left(3);
                s[i] = !s[i];
                s[i] = !s[i];
            }
        }
        154 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(5);
                s[i] = !s[i];
                s[i] ^= s[pos2];
                s[i] ^= s[i].count_ones() as u8;
            }
        }
        155 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
                s[i] ^= s[pos2];
                s[i] ^= s[i].count_ones() as u8;
                s[i] ^= s[pos2];
            }
        }
        156 => {
            for i in pos1..pos2 {
                s[i] >>= s[i] & 3;
                s[i] >>= s[i] & 3;
                s[i] = s[i].rotate_left(3);
                s[i] = s[i].rotate_left(1);
            }
        }
        157 => {
            for i in pos1..pos2 {
                s[i] >>= s[i] & 3;
                s[i] <<= s[i] & 3;
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] = s[i].rotate_left(1);
            }
        }
        158 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].count_ones() as u8;
                s[i] = s[i].rotate_left(3);
                s[i] = s[i].wrapping_add(s[i]);
                s[i] = s[i].rotate_left(1);
            }
        }
        159 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
                s[i] ^= s[pos2];
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] ^= s[pos2];
            }
        }
        160 => {
            for i in pos1..pos2 {
                s[i] >>= s[i] & 3;
                s[i] = s[i].reverse_bits();
                s[i] = s[i].rotate_left(1);
                s[i] = s[i].rotate_left(3);
            }
        }
        161 => {
            for i in pos1..pos2 {
                s[i] ^= s[pos2];
                s[i] ^= s[pos2];
                s[i] = s[i].rotate_left(5);
                s[i] = s[i].rotate_left(s[i] as u32);
            }
        }
        162 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] = s[i].reverse_bits();
                s[i] ^= s[i].rotate_left(2);
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
            }
        }
        163 => {
            for i in pos1..pos2 {
                s[i] <<= s[i] & 3;
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
                s[i] ^= s[i].rotate_left(4);
                s[i] = s[i].rotate_left(1);
            }
        }
        164 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] ^= s[i].count_ones() as u8;
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
                s[i] = !s[i];
            }
        }
        165 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].rotate_left(4);
                s[i] ^= s[pos2];
                s[i] <<= s[i] & 3;
                s[i] = s[i].wrapping_add(s[i]);
            }
        }
        166 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(3);
                s[i] = s[i].wrapping_add(s[i]);
                s[i] ^= s[i].rotate_left(2);
                s[i] = !s[i];
            }
        }
        167 => {
            for i in pos1..pos2 {
                s[i] = !s[i];
                s[i] = !s[i];
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] >>= s[i] & 3;
            }
        }
        168 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] &= s[pos2];
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] = s[i].rotate_left(1);
            }
        }
        169 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(1);
                s[i] <<= s[i] & 3;
                s[i] ^= s[i].rotate_left(4);
                s[i] &= s[pos2];
            }
        }
        170 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
                s[i] = s[i].reverse_bits();
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
                s[i] = s[i].wrapping_mul(s[i]);
            }
        }
        171 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(3);
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
                s[i] ^= s[i].count_ones() as u8;
                s[i] = s[i].reverse_bits();
            }
        }
        172 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].rotate_left(4);
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
                s[i] <<= s[i] & 3;
                s[i] = s[i].rotate_left(1);
            }
        }
        173 => {
            for i in pos1..pos2 {
                s[i] = !s[i];
                s[i] <<= s[i] & 3;
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] = s[i].wrapping_add(s[i]);
            }
        }
        174 => {
            for i in pos1..pos2 {
                s[i] = !s[i];
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] ^= s[i].count_ones() as u8;
                s[i] ^= s[i].count_ones() as u8;
            }
        }
        175 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(3);
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] = s[i].rotate_left(5);
            }
        }
        176 => {
            for i in pos1..pos2 {
                s[i] ^= s[pos2];
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] ^= s[pos2];
                s[i] = s[i].rotate_left(5);
            }
        }
        177 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].count_ones() as u8;
                s[i] ^= s[i].rotate_left(2);
                s[i] ^= s[i].rotate_left(2);
                s[i] &= s[pos2];
            }
        }
        178 => {
            for i in pos1..pos2 {
                s[i] &= s[pos2];
                s[i] = s[i].wrapping_add(s[i]);
                s[i] = !s[i];
                s[i] = s[i].rotate_left(1);
            }
        }
        179 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].rotate_left(2);
                s[i] = s[i].wrapping_add(s[i]);
                s[i] >>= s[i] & 3;
                s[i] = s[i].reverse_bits();
            }
        }
        180 => {
            for i in pos1..pos2 {
                s[i] >>= s[i] & 3;
                s[i] ^= s[i].rotate_left(4);
                s[i] ^= s[pos2];
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
            }
        }
        181 => {
            for i in pos1..pos2 {
                s[i] = !s[i];
                s[i] <<= s[i] & 3;
                s[i] ^= s[i].rotate_left(2);
                s[i] = s[i].rotate_left(5);
            }
        }
        182 => {
            for i in pos1..pos2 {
                s[i] ^= s[pos2];
                s[i] = s[i].rotate_left(1);
                s[i] = s[i].rotate_left(5);
                s[i] ^= s[i].rotate_left(4);
            }
        }
        183 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_add(s[i]);
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
                s[i] = s[i].wrapping_mul(s[i]);
            }
        }
        184 => {
            for i in pos1..pos2 {
                s[i] <<= s[i] & 3;
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] = s[i].rotate_left(5);
                s[i] ^= s[pos2];
            }
        }
        185 => {
            for i in pos1..pos2 {
                s[i] = !s[i];
                s[i] ^= s[i].rotate_left(4);
                s[i] = s[i].rotate_left(5);
                s[i] >>= s[i] & 3;
            }
        }
        186 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].rotate_left(2);
                s[i] ^= s[i].rotate_left(4);
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
                s[i] >>= s[i] & 3;
            }
        }
        187 => {
            for i in pos1..pos2 {
                s[i] ^= s[pos2];
                s[i] = !s[i];
                s[i] = s[i].wrapping_add(s[i]);
                s[i] = s[i].rotate_left(3);
            }
        }
        188 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].rotate_left(4);
                s[i] ^= s[i].count_ones() as u8;
                s[i] ^= s[i].rotate_left(4);
                s[i] ^= s[i].rotate_left(4);
            }
        }
        189 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(5);
                s[i] ^= s[i].rotate_left(4);
                s[i] ^= s[pos2];
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
            }
        }
        190 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(5);
                s[i] >>= s[i] & 3;
                s[i] &= s[pos2];
                s[i] ^= s[i].rotate_left(2);
            }
        }
        191 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_add(s[i]);
                s[i] = s[i].rotate_left(3);
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] >>= s[i] & 3;
            }
        }
        192 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_add(s[i]);
                s[i] <<= s[i] & 3;
                s[i] = s[i].wrapping_add(s[i]);
                s[i] = s[i].wrapping_mul(s[i]);
            }
        }
        193 => {
            for i in pos1..pos2 {
                s[i] &= s[pos2];
                s[i] <<= s[i] & 3;
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] = s[i].rotate_left(1);
            }
        }
        194 => {
            for i in pos1..pos2 {
                s[i] &= s[pos2];
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] <<= s[i] & 3;
                s[i] &= s[pos2];
            }
        }
        195 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].count_ones() as u8;
                s[i] ^= s[i].rotate_left(2);
                s[i] ^= s[pos2];
                s[i] ^= s[i].rotate_left(4);
            }
        }
        196 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(3);
                s[i] = s[i].reverse_bits();
                s[i] <<= s[i] & 3;
                s[i] = s[i].rotate_left(1);
            }
        }
        197 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].rotate_left(4);
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] = s[i].wrapping_mul(s[i]);
            }
        }
        198 => {
            for i in pos1..pos2 {
                s[i] >>= s[i] & 3;
                s[i] >>= s[i] & 3;
                s[i] = s[i].reverse_bits();
                s[i] = s[i].rotate_left(1);
            }
        }
        199 => {
            for i in pos1..pos2 {
                s[i] = !s[i];
                s[i] = s[i].wrapping_add(s[i]);
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] ^= s[pos2];
            }
        }
        200 => {
            for i in pos1..pos2 {
                s[i] >>= s[i] & 3;
                s[i] ^= s[i].count_ones() as u8;
                s[i] = s[i].reverse_bits();
                s[i] = s[i].reverse_bits();
            }
        }
        201 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(3);
                s[i] ^= s[i].rotate_left(2);
                s[i] ^= s[i].rotate_left(4);
                s[i] = !s[i];
            }
        }
        202 => {
            for i in pos1..pos2 {
                s[i] ^= s[pos2];
                s[i] = !s[i];
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] = s[i].rotate_left(5);
            }
        }
        203 => {
            for i in pos1..pos2 {
                s[i] ^= s[pos2];
                s[i] &= s[pos2];
                s[i] = s[i].rotate_left(1);
                s[i] = s[i].rotate_left(s[i] as u32);
            }
        }
        204 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(5);
                s[i] ^= s[i].rotate_left(2);
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] ^= s[pos2];
            }
        }
        205 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].count_ones() as u8;
                s[i] ^= s[i].rotate_left(4);
                s[i] <<= s[i] & 3;
                s[i] = s[i].wrapping_add(s[i]);
            }
        }
        206 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].rotate_left(4);
                s[i] = s[i].reverse_bits();
                s[i] = s[i].reverse_bits();
                s[i] ^= s[i].count_ones() as u8;
            }
        }
        207 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(5);
                s[i] = s[i].rotate_left(3);
                s[i] ^= s[i].count_ones() as u8;
                s[i] ^= s[i].count_ones() as u8;
            }
        }
        208 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_add(s[i]);
                s[i] = s[i].wrapping_add(s[i]);
                s[i] >>= s[i] & 3;
                s[i] = s[i].rotate_left(3);
            }
        }
        209 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(5);
                s[i] = s[i].reverse_bits();
                s[i] ^= s[i].count_ones() as u8;
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
            }
        }
        210 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].rotate_left(2);
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] = s[i].rotate_left(5);
                s[i] = !s[i];
            }
        }
        211 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].rotate_left(4);
                s[i] = s[i].wrapping_add(s[i]);
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
                s[i] = s[i].rotate_left(s[i] as u32);
            }
        }
        212 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] ^= s[i].rotate_left(2);
                s[i] ^= s[pos2];
                s[i] ^= s[pos2];
            }
        }
        213 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_add(s[i]);
                s[i] <<= s[i] & 3;
                s[i] = s[i].rotate_left(3);
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
            }
        }
        214 => {
            for i in pos1..pos2 {
                s[i] ^= s[pos2];
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
                s[i] >>= s[i] & 3;
                s[i] = !s[i];
            }
        }
        215 => {
            for i in pos1..pos2 {
                s[i] ^= s[pos2];
                s[i] &= s[pos2];
                s[i] <<= s[i] & 3;
                s[i] = s[i].wrapping_mul(s[i]);
            }
        }
        216 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] = !s[i];
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
                s[i] &= s[pos2];
            }
        }
        217 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(5);
                s[i] = s[i].wrapping_add(s[i]);
                s[i] = s[i].rotate_left(1);
                s[i] ^= s[i].rotate_left(4);
            }
        }
        218 => {
            for i in pos1..pos2 {
                s[i] = s[i].reverse_bits();
                s[i] = !s[i];
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
            }
        }
        219 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].rotate_left(4);
                s[i] = s[i].rotate_left(3);
                s[i] &= s[pos2];
                s[i] = s[i].reverse_bits();
            }
        }
        220 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(1);
                s[i] <<= s[i] & 3;
                s[i] = s[i].reverse_bits();
                s[i] <<= s[i] & 3;
            }
        }
        221 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(5);
                s[i] ^= s[pos2];
                s[i] = !s[i];
                s[i] = s[i].reverse_bits();
            }
        }
        222 => {
            for i in pos1..pos2 {
                s[i] >>= s[i] & 3;
                s[i] <<= s[i] & 3;
                s[i] ^= s[pos2];
                s[i] = s[i].wrapping_mul(s[i]);
            }
        }
        223 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(3);
                s[i] ^= s[pos2];
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
            }
        }
        224 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].rotate_left(2);
                s[i] = s[i].rotate_left(1);
                s[i] = s[i].rotate_left(3);
                s[i] <<= s[i] & 3;
            }
        }
        225 => {
            for i in pos1..pos2 {
                s[i] = !s[i];
                s[i] >>= s[i] & 3;
                s[i] = s[i].reverse_bits();
                s[i] = s[i].rotate_left(3);
            }
        }
        226 => {
            for i in pos1..pos2 {
                s[i] = s[i].reverse_bits();
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] ^= s[pos2];
            }
        }
        227 => {
            for i in pos1..pos2 {
                s[i] = !s[i];
                s[i] <<= s[i] & 3;
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
                s[i] &= s[pos2];
            }
        }
        228 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_add(s[i]);
                s[i] >>= s[i] & 3;
                s[i] = s[i].wrapping_add(s[i]);
                s[i] ^= s[i].count_ones() as u8;
            }
        }
        229 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(3);
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] ^= s[i].rotate_left(2);
                s[i] ^= s[i].count_ones() as u8;
            }
        }
        230 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] &= s[pos2];
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] = s[i].rotate_left(s[i] as u32);
            }
        }
        231 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(3);
                s[i] >>= s[i] & 3;
                s[i] ^= s[pos2];
                s[i] = s[i].reverse_bits();
            }
        }
        232 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] ^= s[i].rotate_left(4);
                s[i] = s[i].rotate_left(5);
            }
        }
        233 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(1);
                s[i] ^= s[i].count_ones() as u8;
                s[i] = s[i].rotate_left(3);
                s[i] ^= s[i].count_ones() as u8;
            }
        }
        234 => {
            for i in pos1..pos2 {
                s[i] &= s[pos2];
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] >>= s[i] & 3;
                s[i] ^= s[pos2];
            }
        }
        235 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].rotate_left(2);
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] = s[i].rotate_left(3);
                s[i] = !s[i];
            }
        }
        236 => {
            for i in pos1..pos2 {
                s[i] ^= s[pos2];
                s[i] = s[i].wrapping_add(s[i]);
                s[i] &= s[pos2];
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
            }
        }
        237 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(5);
                s[i] <<= s[i] & 3;
                s[i] ^= s[i].rotate_left(2);
                s[i] = s[i].rotate_left(3);
            }
        }
        238 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_add(s[i]);
                s[i] = s[i].wrapping_add(s[i]);
                s[i] = s[i].rotate_left(3);
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
            }
        }
        239 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(5);
                s[i] = s[i].rotate_left(1);
                s[i] = s[i].wrapping_mul(s[i]);
                s[i] &= s[pos2];
            }
        }
        240 => {
            for i in pos1..pos2 {
                s[i] = !s[i];
                s[i] = s[i].wrapping_add(s[i]);
                s[i] &= s[pos2];
                s[i] <<= s[i] & 3;
            }
        }
        241 => {
            for i in pos1..pos2 {
                s[i] ^= s[i].rotate_left(4);
                s[i] ^= s[i].count_ones() as u8;
                s[i] ^= s[pos2];
                s[i] = s[i].rotate_left(1);
            }
        }
        242 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_add(s[i]);
                s[i] = s[i].wrapping_add(s[i]);
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
                s[i] ^= s[pos2];
            }
        }
        243 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(5);
                s[i] ^= s[i].rotate_left(2);
                s[i] ^= s[i].count_ones() as u8;
                s[i] = s[i].rotate_left(1);
            }
        }
        244 => {
            for i in pos1..pos2 {
                s[i] = !s[i];
                s[i] ^= s[i].rotate_left(2);
                s[i] = s[i].reverse_bits();
                s[i] = s[i].rotate_left(5);
            }
        }
        245 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
                s[i] = s[i].rotate_left(5);
                s[i] ^= s[i].rotate_left(2);
                s[i] >>= s[i] & 3;
            }
        }
        246 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_add(s[i]);
                s[i] = s[i].rotate_left(1);
                s[i] >>= s[i] & 3;
                s[i] = s[i].wrapping_add(s[i]);
            }
        }
        247 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(5);
                s[i] ^= s[i].rotate_left(2);
                s[i] = s[i].rotate_left(5);
                s[i] = !s[i];
            }
        }
        248 => {
            for i in pos1..pos2 {
                s[i] = !s[i];
                s[i] = s[i].wrapping_sub(s[i] ^ 97);
                s[i] ^= s[i].count_ones() as u8;
                s[i] = s[i].rotate_left(5);
            }
        }
        249 => {
            for i in pos1..pos2 {
                s[i] = s[i].reverse_bits();
                s[i] ^= s[i].rotate_left(4);
                s[i] ^= s[i].rotate_left(4);
                s[i] = s[i].rotate_left(s[i] as u32);
            }
        }
        250 => {
            for i in pos1..pos2 {
                s[i] &= s[pos2];
                s[i] = s[i].rotate_left(s[i] as u32);
                s[i] ^= s[i].count_ones() as u8;
                s[i] ^= s[i].rotate_left(4);
            }
        }
        251 => {
            for i in pos1..pos2 {
                s[i] = s[i].wrapping_add(s[i]);
                s[i] ^= s[i].count_ones() as u8;
                s[i] = s[i].reverse_bits();
                s[i] ^= s[i].rotate_left(2);
            }
        }
        252 => {
            for i in pos1..pos2 {
                s[i] = s[i].reverse_bits();
                s[i] ^= s[i].rotate_left(4);
                s[i] ^= s[i].rotate_left(2);
                s[i] <<= s[i] & 3;
            }
        }
        253 => {
            for i in pos1..pos2 {
                s[i] = s[i].rotate_left(3);
                s[i] ^= s[i].rotate_left(2);
                s[i] ^= s[pos2];
                s[i] = s[i].rotate_left(3);
                prev_lhash = lhash.wrapping_add(prev_lhash);
                lhash = xxh64(&s[..pos2 as usize], 0);
            }
        }
        254 => {
            *rc4s = Rc4::new(s);
            for i in pos1..pos2 {
                s[i] ^= s[i].count_ones() as u8;
                s[i] = s[i].rotate_left(3);
                s[i] ^= s[i].rotate_left(2);
                s[i] = s[i].rotate_left(3);
            }
        }
        255 => {
            *rc4s = Rc4::new(s);
            for i in pos1..pos2 {
                s[i] ^= s[i].count_ones() as u8;
                s[i] = s[i].rotate_left(3);
                s[i] ^= s[i].rotate_left(2);
                s[i] = s[i].rotate_left(3);
            }
        }
        _ => {}
    }
    *lhash_out = lhash;
    *prev_out = prev_lhash;
}
