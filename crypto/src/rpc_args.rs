// SPDX-License-Identifier: BSD-3-Clause
//
//! SCDATA argument serialization — mirrors derohe `rpc/rpc.go`
//! (`Arguments.MarshalBinary` / `UnmarshalBinary`).
//!
//! The wire format is canonical CBOR (fxamacker/cbor/v2 with
//! SortCoreDeterministic, ShortestFloat16, NaNConvert7e00,
//! InfConvertFloat16, IndefLengthForbidden, TimeTag EncTagRequired):
//! a map whose keys are "name + datatype-char" (S,I,U,F,H,A,T) and whose
//! values are the typed argument values:
//!   string  -> text string
//!   int64   -> CBOR int
//!   uint64  -> CBOR unsigned
//!   float64 -> float16 if exactly representable, else float32 if exactly
//!              representable, else float64 (NaN -> 0x7e00, ±Inf -> half)
//!   hash    -> byte string (32)
//!   address -> byte string (33, compressed public key)
//!   time    -> tag 1 + integer Unix seconds (default TimeUnix mode)
//! Zero time encodes as CBOR null.

pub const DATA_STRING: u8 = b'S';
pub const DATA_INT64: u8 = b'I';
pub const DATA_UINT64: u8 = b'U';
pub const DATA_FLOAT64: u8 = b'F';
pub const DATA_HASH: u8 = b'H';
pub const DATA_ADDRESS: u8 = b'A';
pub const DATA_TIME: u8 = b'T';

#[derive(Debug, Clone, PartialEq)]
pub enum ArgValue {
    Str(String),
    I64(i64),
    U64(u64),
    F64(f64),
    Hash([u8; 32]),
    Addr([u8; 33]),
    /// Unix seconds + optional sub-second (nanos). Mirrors Go time.Time.
    Time {
        secs: i64,
        nanos: u32,
    },
    /// Zero time -> CBOR null.
    TimeZero,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Argument {
    pub name: String,
    pub data_type: u8,
    pub value: ArgValue,
}

/// SCACTION / SCCODE / SC_ID argument names (rpc sc_* constants).
pub const SC_ACTION: &str = "SC_ACTION";
pub const SC_CODE: &str = "SC_CODE";
pub const SC_ID: &str = "SC_ID";

/// rpc.Arguments — a vec of Argument (newtype so we can impl methods).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Arguments(pub Vec<Argument>);

impl Arguments {
    pub fn get(&self, name: &str) -> Option<&Argument> {
        self.0.iter().find(|a| a.name == name)
    }
    pub fn get_uint64(&self, name: &str) -> Option<u64> {
        match self.get(name) {
            Some(Argument {
                value: ArgValue::U64(v),
                ..
            }) => Some(*v),
            _ => None,
        }
    }
    pub fn get_string(&self, name: &str) -> Option<String> {
        match self.get(name) {
            Some(Argument {
                value: ArgValue::Str(v),
                ..
            }) => Some(v.clone()),
            _ => None,
        }
    }
    pub fn get_hash(&self, name: &str) -> Option<[u8; 32]> {
        match self.get(name) {
            Some(Argument {
                value: ArgValue::Hash(v),
                ..
            }) => Some(*v),
            _ => None,
        }
    }
    pub fn iter(&self) -> std::slice::Iter<'_, Argument> {
        self.0.iter()
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

// ---------------------------------------------------------------------------
// CBOR primitives
// ---------------------------------------------------------------------------

fn head(major: u8, n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    match n {
        0..=23 => out.push((major << 5) | n as u8),
        0..=0xff => {
            out.push((major << 5) | 24);
            out.push(n as u8);
        }
        0..=0xffff => {
            out.push((major << 5) | 25);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        0..=0xffff_ffff => {
            out.push((major << 5) | 26);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
        _ => {
            out.push((major << 5) | 27);
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
    out
}

fn enc_text(s: &str) -> Vec<u8> {
    let mut out = head(3, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
    out
}

fn enc_bytes(b: &[u8]) -> Vec<u8> {
    let mut out = head(2, b.len() as u64);
    out.extend_from_slice(b);
    out
}

fn enc_uint(n: u64) -> Vec<u8> {
    head(0, n)
}

fn enc_int(v: i64) -> Vec<u8> {
    if v >= 0 {
        head(0, v as u64)
    } else {
        head(1, (-1 - v) as u64)
    }
}

/// Round-to-nearest-even float32 -> float16 (fxamacker float16 package
/// semantics: subnormal f32 values are flushed via normal rounding, NaN/Inf
/// pass through with quiet/sign preserved).
fn f32_to_f16_bits(f: f32) -> u16 {
    let bits = f.to_bits();
    let sign = ((bits >> 16) & 0x8000) as u16;
    let exp = ((bits >> 23) & 0xff) as i32;
    let mant = bits & 0x7f_ffff;

    if exp == 0xff {
        // Inf/NaN
        if mant == 0 {
            return sign | 0x7c00;
        }
        return sign | 0x7e00; // quiet NaN
    }

    let mut e = exp - 127 + 15;
    let mut m = mant;

    if exp == 0 {
        // f32 subnormal: value = mant * 2^-149. f16 subnormals start at 2^-24.
        // Normalize: find the highest set bit, shift so it aligns to the
        // f16 normal boundary; if it lands in the subnormal range, round.
        if mant == 0 {
            return sign; // ±0
        }
        // count leading zeros in the 23-bit mantissa
        let lz = mant.leading_zeros() as i32 - 9; // bits above bit 23
                                                  // value exponent = -149 + (23 - lz) = -126 - lz
                                                  // as f16: exponent field e16 = -126 - lz + 15 = -111 - lz
        e = -111 - lz;
        if e >= -14 {
            // fits as normal f16: shift mantissa left to remove leading zeros
            m <<= lz; // mantissa now has its top bit at bit 23... but f16 wants 10 bits
                      // re-enter the normal path with the same rounding
            e = -111 - lz + lz; // this is getting confusing; recompute below
        }
    }

    // e is the f16 exponent bias-adjusted value (normal or subnormal candidate)
    if e >= 31 {
        // overflow to infinity (caller checks exactness via roundtrip)
        return sign | 0x7c00;
    }
    if e <= -25 {
        // underflow to zero (round-to-nearest-even at the boundary)
        return sign;
    }
    if e >= -14 {
        // normal f16: keep 10 mantissa bits, round-to-nearest-even at bit 13
        let rounded = m + 0x1000; // 1 << 12 (half of 1<<13)
                                  // handle mantissa overflow into exponent
        let carry = (rounded >> 23) & 1;
        let m10 = ((rounded >> 13) & 0x3ff) as u16;
        let e_new = e + carry as i32;
        if e_new >= 31 {
            return sign | 0x7c00;
        }
        return sign | ((e_new as u16) << 10) | m10;
    }
    // f16 subnormal: value = mant * 2^(e - 14 - 10) where mant has 23 bits
    // subnormal f16 exponent is fixed at 2^-24; mantissa shift = -e - 14
    let shift = (-e - 14) as u32; // 1..=10
    let round_bit = 1u32 << (shift - 1);
    let half = (m >> shift) & 1;
    let mut m10 = m >> shift;
    let rem = m & ((1u32 << shift) - 1);
    if rem > round_bit || (rem == round_bit && half == 1) {
        m10 += 1;
    }
    if m10 == 0x400 {
        // rounded up into normal range
        return sign | 0x0400;
    }
    sign | (m10 as u16)
}

fn f16_bits_to_f32(bits: u16) -> f32 {
    let sign = ((bits >> 15) & 1) as u32;
    let exp = ((bits >> 10) & 0x1f) as u32;
    let mant = (bits & 0x3ff) as u32;
    if exp == 0 {
        if mant == 0 {
            return f32::from_bits(sign << 31);
        }
        // subnormal: mant * 2^-24
        return f32::from_bits((sign << 31) | (mant << 13));
    }
    if exp == 31 {
        if mant == 0 {
            return f32::from_bits((sign << 31) | 0x7f80_0000);
        }
        return f32::from_bits((sign << 31) | 0x7fc0_0000);
    }
    f32::from_bits((sign << 31) | ((exp + 112) << 23) | (mant << 13))
}

/// fxamacker ShortestFloat: float16 if exactly representable, else float32
/// if exactly representable, else float64. NaN -> 0x7e00, ±Inf -> half.
fn enc_float(v: f64) -> Vec<u8> {
    if v.is_nan() {
        return vec![0xf9, 0x7e, 0x00];
    }
    if v.is_infinite() {
        if v > 0.0 {
            return vec![0xf9, 0x7c, 0x00];
        }
        return vec![0xf9, 0xfc, 0x00];
    }
    let f32v = v as f32;
    if f64::from(f32v) != v {
        // cannot fit float32: encode float64
        let mut out = vec![0xfb];
        out.extend_from_slice(&v.to_bits().to_be_bytes());
        return out;
    }
    let f16 = f32_to_f16_bits(f32v);
    if f16_bits_to_f32(f16) == f32v {
        let mut out = vec![0xf9];
        out.extend_from_slice(&f16.to_be_bytes());
        return out;
    }
    let mut out = vec![0xfa];
    out.extend_from_slice(&f32v.to_bits().to_be_bytes());
    out
}

fn enc_value(v: &ArgValue) -> Vec<u8> {
    match v {
        ArgValue::Str(s) => enc_text(s),
        ArgValue::I64(i) => enc_int(*i),
        ArgValue::U64(u) => enc_uint(*u),
        ArgValue::F64(f) => enc_float(*f),
        ArgValue::Hash(h) => enc_bytes(h),
        ArgValue::Addr(a) => enc_bytes(a),
        ArgValue::Time { secs, nanos } => {
            let mut out = vec![0xc1]; // tag 1
            if *nanos == 0 {
                out.extend_from_slice(&enc_int(*secs));
            } else {
                let f = *secs as f64 + f64::from(*nanos) / 1e9;
                out.extend_from_slice(&enc_float(f));
            }
            out
        }
        ArgValue::TimeZero => vec![0xf6], // CBOR null
    }
}

// ---------------------------------------------------------------------------
// MarshalBinary
// ---------------------------------------------------------------------------

/// Canonical CBOR map key sort: shorter first, then bytewise (RFC 7049
/// core deterministic / fxamacker SortCoreDeterministic).
fn sort_keys<'a>(entries: &mut Vec<(&'a str, &'a ArgValue)>) {
    entries.sort_by(|a, b| {
        a.0.len()
            .cmp(&b.0.len())
            .then_with(|| a.0.as_bytes().cmp(b.0.as_bytes()))
    });
}

impl Arguments {
    /// Go `Arguments.MarshalBinary`. Duplicate name+type keys: last wins.
    /// Returns Err when a name is empty or a datatype is unknown.
    pub fn marshal_binary(&self) -> Result<Vec<u8>, String> {
        // dedupe by name+datatype, last wins (Go localmap semantics)
        let mut map: Vec<(String, ArgValue)> = Vec::new();
        for arg in &self.0 {
            if arg.name.is_empty() {
                return Err("Name must be atleast 1 char long".into());
            }
            let key = format!("{}{}", arg.name, arg.data_type as char);
            map.retain(|(k, _)| *k != key);
            map.push((key, arg.value.clone()));
        }
        let mut entries: Vec<(&str, &ArgValue)> =
            map.iter().map(|(k, v)| (k.as_str(), v)).collect();
        sort_keys(&mut entries);
        let mut out = head(5, entries.len() as u64);
        for (k, v) in entries {
            out.extend_from_slice(&enc_text(k));
            out.extend_from_slice(&enc_value(v));
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// UnmarshalBinary (subset decoder for the same value types)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Cbor2 {
    Uint(u64),
    Neg(i64),
    Bytes(Vec<u8>),
    Text(String),
    Float(f64),
    Null,
    Tag(u64, Box<Cbor2>),
    Bool(bool),
    Undefined,
    Map(Vec<(Cbor2, Cbor2)>),
}

struct Reader2<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader2<'a> {
    fn byte(&mut self) -> Result<u8, String> {
        if self.pos >= self.buf.len() {
            return Err("cbor: unexpected end".into());
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        Ok(b)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.buf.len() - self.pos < n {
            return Err("cbor: unexpected end".into());
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn arg(&mut self, n: u64) -> Result<u64, String> {
        match n {
            0..=23 => Ok(n),
            24 => Ok(u64::from(self.byte()?)),
            25 => {
                let b = self.take(2)?;
                Ok(u64::from(u16::from_be_bytes([b[0], b[1]])))
            }
            26 => {
                let b = self.take(4)?;
                Ok(u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]])))
            }
            27 => {
                let b = self.take(8)?;
                Ok(u64::from_be_bytes(b.try_into().unwrap()))
            }
            _ => Err("cbor: bad additional info".into()),
        }
    }
    fn value(&mut self) -> Result<Cbor2, String> {
        let ib = self.byte()?;
        let major = ib >> 5;
        let ai = u64::from(ib & 0x1f);
        match major {
            0 => Ok(Cbor2::Uint(self.arg(ai)?)),
            1 => {
                let n = self.arg(ai)?;
                Ok(Cbor2::Neg(-1i64 - n as i64))
            }
            2 => {
                let n = self.arg(ai)?;
                Ok(Cbor2::Bytes(self.take(n as usize)?.to_vec()))
            }
            3 => {
                let n = self.arg(ai)?;
                let b = self.take(n as usize)?;
                Ok(Cbor2::Text(String::from_utf8_lossy(b).into_owned()))
            }
            5 => {
                let n = self.arg(ai)?;
                let mut map = Vec::new();
                for _ in 0..n {
                    let k = self.value()?;
                    let v = self.value()?;
                    map.push((k, v));
                }
                Ok(Cbor2::Map(map))
            }
            6 => {
                let t = self.arg(ai)?;
                let v = self.value()?;
                Ok(Cbor2::Tag(t, Box::new(v)))
            }
            7 => match ai {
                20 => Ok(Cbor2::Bool(false)),
                21 => Ok(Cbor2::Bool(true)),
                22 => Ok(Cbor2::Null),
                23 => Ok(Cbor2::Undefined),
                25 => {
                    let b = self.take(2)?;
                    let h = u16::from_be_bytes([b[0], b[1]]);
                    Ok(Cbor2::Float(f64::from(f16_bits_to_f32(h))))
                }
                26 => {
                    let b = self.take(4)?;
                    Ok(Cbor2::Float(f64::from(f32::from_bits(u32::from_be_bytes(
                        b.try_into().unwrap(),
                    )))))
                }
                27 => {
                    let b = self.take(8)?;
                    Ok(Cbor2::Float(f64::from_bits(u64::from_be_bytes(
                        b.try_into().unwrap(),
                    ))))
                }
                _ => Err("cbor: unsupported primitive".into()),
            },
            _ => Err("cbor: unsupported major type".into()),
        }
    }
}

impl Arguments {
    /// Go `Arguments.UnmarshalBinary`: parse the CBOR map, rebuild the typed
    /// arguments, then sort by name (Go args.Sort()). Round-trips our own
    /// marshal output byte-for-byte in content.
    pub fn unmarshal_binary(data: &[u8]) -> Result<Arguments, String> {
        let mut r = Reader2 { buf: data, pos: 0 };
        let root = r.value()?;
        let map = match root {
            Cbor2::Map(m) => m,
            _ => return Err("scdata: expected map".into()),
        };
        let mut args = Vec::new();
        for (k, v) in map {
            let key = match k {
                Cbor2::Text(s) => s,
                _ => return Err("scdata: non-text map key".into()),
            };
            if key.len() < 2 {
                return Err(format!("Invalid encoding for key '{}'", key));
            }
            let name = key[..key.len() - 1].to_string();
            let dtype = key.as_bytes()[key.len() - 1];
            let value = match dtype {
                DATA_INT64 => match v {
                    Cbor2::Uint(u) => ArgValue::I64(u as i64),
                    Cbor2::Neg(i) => ArgValue::I64(i),
                    _ => return Err("scdata: int64 value type mismatch".into()),
                },
                DATA_UINT64 => match v {
                    Cbor2::Uint(u) => ArgValue::U64(u),
                    _ => return Err("scdata: uint64 value type mismatch".into()),
                },
                DATA_FLOAT64 => match v {
                    Cbor2::Float(f) => ArgValue::F64(f),
                    _ => return Err("scdata: float64 value type mismatch".into()),
                },
                DATA_HASH => match v {
                    Cbor2::Bytes(b) => {
                        let mut h = [0u8; 32];
                        let n = b.len().min(32);
                        h[..n].copy_from_slice(&b[..n]);
                        ArgValue::Hash(h)
                    }
                    _ => return Err("scdata: hash value type mismatch".into()),
                },
                DATA_ADDRESS => match v {
                    Cbor2::Bytes(b) => {
                        let mut a = [0u8; 33];
                        let n = b.len().min(33);
                        a[..n].copy_from_slice(&b[..n]);
                        ArgValue::Addr(a)
                    }
                    _ => return Err("scdata: address value type mismatch".into()),
                },
                DATA_STRING => match v {
                    Cbor2::Text(s) => ArgValue::Str(s),
                    _ => return Err("scdata: string value type mismatch".into()),
                },
                DATA_TIME => match v {
                    Cbor2::Null => ArgValue::TimeZero,
                    Cbor2::Tag(1, inner) => match *inner {
                        Cbor2::Uint(u) => ArgValue::Time {
                            secs: u as i64,
                            nanos: 0,
                        },
                        Cbor2::Neg(i) => ArgValue::Time { secs: i, nanos: 0 },
                        Cbor2::Float(f) => {
                            let secs = f.trunc() as i64;
                            let nanos = ((f - f.trunc()) * 1e9).round() as u32;
                            ArgValue::Time { secs, nanos }
                        }
                        _ => return Err("scdata: time tag value mismatch".into()),
                    },
                    _ => return Err("scdata: time value mismatch".into()),
                },
                _ => return Err(format!("I don't know about type {}", dtype as char)),
            };
            args.push(Argument {
                name,
                data_type: dtype,
                value,
            });
        }
        // Go args.Sort(): by Name only
        args.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
        Ok(Arguments(args))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbor_float16_known() {
        // 1.5 -> half 0x3e00; 0.0 -> 0; -2.0 -> 0xc000
        assert_eq!(f32_to_f16_bits(1.5), 0x3e00);
        assert_eq!(f32_to_f16_bits(0.0), 0x0000);
        assert_eq!(f32_to_f16_bits(-0.0), 0x8000);
        assert_eq!(f32_to_f16_bits(-2.0), 0xc000);
        assert_eq!(f32_to_f16_bits(65504.0), 0x7bff);
        // roundtrip exactness
        assert_eq!(f16_bits_to_f32(f32_to_f16_bits(1.5)), 1.5);
        assert_eq!(f16_bits_to_f32(f32_to_f16_bits(0.1)) != 0.1, true); // 0.1 not exact in f16
    }

    #[test]
    fn args_roundtrip() {
        let args: Arguments = Arguments(vec![
            Argument {
                name: "name".into(),
                data_type: DATA_STRING,
                value: ArgValue::Str("hello".into()),
            },
            Argument {
                name: "amt".into(),
                data_type: DATA_UINT64,
                value: ArgValue::U64(1234567890123),
            },
            Argument {
                name: "neg".into(),
                data_type: DATA_INT64,
                value: ArgValue::I64(-42),
            },
            Argument {
                name: "f".into(),
                data_type: DATA_FLOAT64,
                value: ArgValue::F64(1.5),
            },
            Argument {
                name: "h".into(),
                data_type: DATA_HASH,
                value: ArgValue::Hash([9u8; 32]),
            },
            Argument {
                name: "t".into(),
                data_type: DATA_TIME,
                value: ArgValue::Time {
                    secs: 1700000000,
                    nanos: 0,
                },
            },
        ]);
        let bytes = args.marshal_binary().unwrap();
        // canonical: sorted by length then bytewise
        let back = Arguments::unmarshal_binary(&bytes).unwrap();
        // content equality (order may differ by sort rule)
        let mut a = args.clone();
        a.0.sort_by(|x, y| x.name.as_bytes().cmp(y.name.as_bytes()));
        assert_eq!(back.0.len(), a.0.len());
        for (x, y) in back.0.iter().zip(a.0.iter()) {
            assert_eq!(x.name, y.name);
            assert_eq!(x.data_type, y.data_type);
            assert_eq!(x.value, y.value);
        }
    }

    #[test]
    fn args_zero_time_is_null() {
        let args: Arguments = Arguments(vec![Argument {
            name: "z".into(),
            data_type: DATA_TIME,
            value: ArgValue::TimeZero,
        }]);
        let bytes = args.marshal_binary().unwrap();
        assert!(bytes.contains(&0xf6));
    }
}
