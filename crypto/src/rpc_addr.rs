// SPDX-License-Identifier: BSD-3-Clause
//
//! DERO bech32 address <-> compressed-key helpers for the DVM address
//! builtins (address_raw / address_string). Mirrors rpc/address.go +
//! rpc/bech32.go: data = 0x01 version ‖ 33-byte compressed key, 8→5
//! convertbits, bech32("dero").

/// Bech32 DERO address -> 33-byte compressed public key.
pub fn address_to_compressed(addr: &str) -> Result<Vec<u8>, String> {
    let (hrp, data) = bech32_decode(addr)?;
    if !(hrp == "dero" || hrp == "deroi" || hrp == "deto" || hrp == "detoi" || hrp == "deroproof") {
        return Err("invalid human-readable part".into());
    }
    let res = convertbits(&data, 5, 8, false)?;
    if res.is_empty() || res[0] != 1 {
        return Err(format!("invalid address version : {:?}", res.first()));
    }
    let resbytes: Vec<u8> = res[1..].iter().map(|&b| b as u8).collect();
    if resbytes.len() < 33 {
        return Err(format!("invalid address length as per spec : {}", resbytes.len()));
    }
    Ok(resbytes[..33].to_vec())
}

/// 33-byte compressed public key -> bech32 DERO address string.
pub fn compressed_to_address(pk: &[u8]) -> Result<String, String> {
    if pk.len() != 33 {
        return Err("key must be 33 bytes".into());
    }
    let mut data_bytes = Vec::with_capacity(34);
    data_bytes.push(1u8); // version
    data_bytes.extend_from_slice(pk);
    let data_ints: Vec<usize> = data_bytes.iter().map(|&b| b as usize).collect();
    let data = convertbits(&data_ints, 8, 5, true)?;
    bech32_encode("dero", &data)
}

// bech32 (rpc/bech32.go) — standard scheme.
const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn polymod(values: &[usize]) -> u32 {
    let mut chk: u32 = 1;
    let gen: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    for &v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ (v as u32);
        for (i, &g) in gen.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<usize> {
    let mut v = Vec::new();
    for &b in hrp.as_bytes() {
        v.push((b >> 5) as usize);
    }
    v.push(0);
    for &b in hrp.as_bytes() {
        v.push((b & 31) as usize);
    }
    v
}

fn bech32_decode(s: &str) -> Result<(String, Vec<usize>), String> {
    let s = s.to_ascii_lowercase();
    let pos = s.rfind('1').ok_or("no separator")?;
    let hrp = &s[..pos];
    let data_part = &s[pos + 1..];
    let mut values = Vec::new();
    for c in data_part.chars() {
        let idx = CHARSET.iter().position(|&a| a as char == c).ok_or("invalid character")?;
        values.push(idx);
    }
    let mut exp = hrp_expand(hrp);
    exp.extend_from_slice(&values);
    if polymod(&exp) != 1 {
        return Err("bad checksum".into());
    }
    let data = values[..values.len() - 6].to_vec();
    Ok((hrp.to_string(), data))
}

fn bech32_encode(hrp: &str, data: &[usize]) -> Result<String, String> {
    let mut exp = hrp_expand(hrp);
    exp.extend_from_slice(data);
    exp.extend_from_slice(&[0; 6]);
    let pm = polymod(&exp) ^ 1;
    let mut out = String::new();
    out.push_str(hrp);
    out.push('1');
    for &v in data {
        out.push(CHARSET[v] as char);
    }
    for i in 0..6 {
        out.push(CHARSET[((pm >> (5 * (5 - i))) & 31) as usize] as char);
    }
    Ok(out)
}

/// Go convertbits (rpc/bech32.go).
fn convertbits(data: &[usize], frombits: usize, tobits: usize, pad: bool) -> Result<Vec<usize>, String> {
    let mut acc: u32 = 0;
    let mut bits: usize = 0;
    let mut ret = Vec::new();
    let maxv: u32 = (1 << tobits) - 1;
    let max_acc: u32 = (1 << (frombits + tobits - 1)) - 1;
    for &value in data {
        if (value as u32) >> frombits != 0 {
            return Err("invalid data range".into());
        }
        acc = ((acc << frombits) | value as u32) & max_acc;
        bits += frombits;
        while bits >= tobits {
            bits -= tobits;
            ret.push(((acc >> bits) & maxv) as usize);
        }
    }
    if pad {
        if bits > 0 {
            ret.push(((acc << (tobits - bits)) & maxv) as usize);
        }
    } else if bits >= frombits || ((acc << (tobits - bits)) & maxv) != 0 {
        return Err("illegal zero padding".into());
    }
    Ok(ret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bech32_known() {
        // mainnet test address (from the user's wallet)
        let addr = "dero1qyhfrd0pgtrwmnec9lzeqv38n4dj3q5zrtqrhqlaxngcucfj5vhnkqq6pn8fq";
        let pk = address_to_compressed(addr).unwrap();
        assert_eq!(pk.len(), 33);
        let back = compressed_to_address(&pk).unwrap();
        assert_eq!(back, addr);
    }
}
