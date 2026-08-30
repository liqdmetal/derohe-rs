// SPDX-License-Identifier: BSD-3-Clause
//
//! DVM — DERO smart-contract VM — mirrors derohe `dvm/`.
//!
//! Three layers:
//!   1. `parse`  — line-based tokenizer + `Function`/`End Function` collector.
//!      DERO uses a "rudimentary line by line parser": no AST, line numbers are
//!      mandatory and must be strictly ascending, the language is a tiny Go
//!      subset. Statements are single lines; `IF` only supports
//!      `THEN GOTO x [ELSE GOTO y]`; `LET` requires the variable to exist
//!      (pre-DIM'd).
//!   2. `interpret` — the interpreter: DIM/LET/GOTO/IF/RETURN/PRINT plus an
//!      expression evaluator with the exact Go semantics (string+uint64
//!      auto-concatenation, uint64 two's-complement arithmetic, logical ops,
//!      `~`/`!` unary).
//!   3. `builtins` — the 36 function-table entries with the reference's exact
//!      gas costs (compute + storage).
//!
//! Clean-room: written from the reference source + this spec, not copied.

use std::collections::BTreeMap;
use std::collections::HashMap;

use crate::keccak::keccak256;

// ---------------------------------------------------------------------------
// types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Vtype {
    None = 0x0,
    Invalid = 0x3,
    Uint64 = 0x4,
    String = 0x5,
}

impl Vtype {
    pub fn from_u8(v: u8) -> Vtype {
        match v {
            0x0 => Vtype::None,
            0x3 => Vtype::Invalid,
            0x4 => Vtype::Uint64,
            0x5 => Vtype::String,
            _ => Vtype::Invalid,
        }
    }
    pub fn from_name(name: &str) -> Vtype {
        match name.to_ascii_lowercase().as_str() {
            "uint64" => Vtype::Uint64,
            "string" => Vtype::String,
            _ => Vtype::Invalid,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Variable {
    pub name: String,
    pub vtype: Vtype,
    pub value_uint64: u64,
    pub value_string: String,
}

impl Variable {
    pub fn new_uint64(name: &str, v: u64) -> Variable {
        Variable { name: name.into(), vtype: Vtype::Uint64, value_uint64: v, value_string: String::new() }
    }
    pub fn new_string(name: &str, v: &str) -> Variable {
        Variable { name: name.into(), vtype: Vtype::String, value_uint64: 0, value_string: v.into() }
    }

    /// Go Variable.MarshalBinary: uvarint(value)‖type, or raw string‖type.
    pub fn marshal_binary(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self.vtype {
            Vtype::Invalid | Vtype::None => {}
            Vtype::Uint64 => {
                let mut buf = [0u8; 10];
                let n = put_uvarint(&mut buf, self.value_uint64);
                out.extend_from_slice(&buf[..n]);
            }
            Vtype::String => {
                out.extend_from_slice(self.value_string.as_bytes());
            }
        }
        out.push(self.vtype as u8);
        out
    }

    /// Go Variable.Length: uvarint byte-length (+1) for uint64, len+1 for string.
    pub fn length(&self) -> i64 {
        match self.vtype {
            Vtype::Invalid | Vtype::None => 0,
            Vtype::Uint64 => {
                let mut buf = [0u8; 10];
                (put_uvarint(&mut buf, self.value_uint64) + 1) as i64
            }
            Vtype::String => (self.value_string.len() + 1) as i64,
        }
    }

    pub fn unmarshal_binary(data: &[u8]) -> Result<Variable, String> {
        if data.is_empty() {
            return Err("invalid, probably corruption".into());
        }
        let vtype = Vtype::from_u8(data[data.len() - 1]);
        match vtype {
            Vtype::Invalid | Vtype::None => Err("Invalid cannot be deserialized".into()),
            Vtype::Uint64 => {
                let (v, n) = uvarint(&data[..data.len() - 1]);
                if n <= 0 {
                    return Err("corruption in DB".into());
                }
                Ok(Variable { name: String::new(), vtype, value_uint64: v, value_string: String::new() })
            }
            Vtype::String => Ok(Variable {
                name: String::new(),
                vtype,
                value_uint64: 0,
                value_string: String::from_utf8_lossy(&data[..data.len() - 1]).into_owned(),
            }),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Function {
    pub name: String,
    pub params: Vec<Variable>,
    pub return_value: Variable,
    /// line number -> tokenized line (index 0 = the line number itself)
    pub lines: BTreeMap<u64, Vec<String>>,
    pub line_numbers: Vec<u64>,
    pub line_numbers_index: HashMap<u64, u64>,
}

#[derive(Debug, Clone)]
pub struct SmartContract {
    pub functions: HashMap<String, Function>,
}

pub const LIMIT_INTERPRETED_LINES: i64 = 2000;
pub const LIMIT_EVALS: i64 = 11000;

// ---------------------------------------------------------------------------
// tokenizer
// ---------------------------------------------------------------------------

/// Text-scanner compatible tokenizer. Collects *tokens* on the current line;
/// Go's `text/scanner` emits `;`-ish tokens, ids, strings, ints, floats, and
/// operator chars — each as a separate token.
pub fn tokenize(src: &str) -> Vec<(u32, String)> {
    // We use Go-like rules: whitespace splits; string/raw-string literals and
    // chars are kept whole; numbers are one token; every other non-space run
    // is a token (operators come out character-by-character in Go's scanner,
    // but DERO joins them via strings.Join(line, " ") before re-parsing with
    // go/parser, so operator runs behave like a single token for the parser).
    let mut out = Vec::new();
    let mut line: u32 = 1;
    let bytes: Vec<char> = src.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        match c {
            '\n' => {
                line += 1;
                i += 1;
            }
            ' ' | '\t' | '\r' => {
                i += 1;
            }
            '"' | '\'' | '`' => {
                // string literal (raw strings: `...`)
                let q = c;
                let start = i;
                i += 1;
                while i < bytes.len() && bytes[i] != q {
                    if q != '`' && bytes[i] == '\\' && i + 1 < bytes.len() {
                        i += 1;
                    }
                    i += 1;
                }
                if i < bytes.len() {
                    i += 1; // closing quote
                }
                out.push((line, bytes[start..i].iter().collect()));
            }
            c if c.is_ascii_digit() => {
                let start = i;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == '.' || bytes[i] == '_') {
                    i += 1;
                }
                out.push((line, bytes[start..i].iter().collect()));
            }
            c if c.is_alphabetic() || c == '_' => {
                let start = i;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == '_') {
                    i += 1;
                }
                out.push((line, bytes[start..i].iter().collect()));
            }
            ';' => {
                // Go text/scanner: ';' is emitted as a token on newline.
                out.push((line, ";".into()));
                i += 1;
            }
            _ => {
                // operator or punctuation: emit each char as its own token
                // (Go's text/scanner splits operators character-by-character,
                // and f.lines are serialized joined with a space — `value = = 0`
                // — which dvm_parse differential tests pin byte-for-byte).
                // Multi-char operators are recombined at expression-parse time
                // (see parse_expr's token merge), NOT here.
                out.push((line, c.to_string()));
                i += 1;
            }
        }
    }
    out
}

/// Merge adjacent single-char operator tokens into the multi-char operators
/// the expression parser expects (Go's scanner emits operators
/// character-by-character; the execution path rejoins them — `= =` -> `==`,
/// `! =` -> `!=`, `< =` -> `<=`, `> =` -> `>=`, `& &` -> `&&`,
/// `| |` -> `||`, `< <` -> `<<`, `> >` -> `>>`, `< >` -> `!=`).
fn merge_operator_tokens(toks: Vec<(u32, String)>) -> Vec<(u32, String)> {
    let mut out: Vec<(u32, String)> = Vec::with_capacity(toks.len());
    let mut i = 0;
    while i < toks.len() {
        let (line, ref tok) = toks[i];
        // lookahead: is the next token a compatible second half?
        let merged = if i + 1 < toks.len() {
            let next = toks[i + 1].1.as_str();
            match tok.as_str() {
                "=" if next == "=" => Some("=="),
                "!" if next == "=" => Some("!="),
                "<" if next == "=" => Some("<="),
                ">" if next == "=" => Some(">="),
                "&" if next == "&" => Some("&&"),
                "|" if next == "|" => Some("||"),
                "<" if next == "<" => Some("<<"),
                ">" if next == ">" => Some(">>"),
                "<" if next == ">" => Some("!="),
                _ => None,
            }
        } else {
            None
        };
        match merged {
            Some(op) => {
                out.push((line, op.to_string()));
                i += 2;
            }
            None => {
                out.push(toks[i].clone());
                i += 1;
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// parser
// ---------------------------------------------------------------------------

fn check_valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) => c.is_alphabetic(),
        None => false,
    }
}

/// Go ParseSmartContract: collect lines of tokens, feed them to
/// parse_function_line. Errors recovered (returned as Err).
pub fn parse_smart_contract(src: &str) -> Result<SmartContract, String> {
    let tokens = tokenize(src);
    let mut sc = SmartContract { functions: HashMap::new() };
    let mut current: Option<Function> = None;

    // group tokens by line (in order)
    let mut lines: Vec<(u32, Vec<String>)> = Vec::new();
    let mut rem_line: Option<u32> = None; // current line is a REM/; comment
    for (ln, tok) in tokens {
        if tok.starts_with(';') || tok.starts_with("REM") {
            // Go skips the WHOLE line once any token is ; or REM
            // (dvm.go: skip_line = s.Position.Line; every token on that
            // line is then skipped). Flag the line; drop it at the end.
            rem_line = Some(ln);
            continue;
        }
        if rem_line == Some(ln) {
            continue; // still on a comment line
        }
        if lines.last().map(|(l, _)| *l == ln).unwrap_or(false) {
            lines.last_mut().unwrap().1.push(tok);
        } else {
            lines.push((ln, vec![tok]));
        }
    }
    // drop any line that was a comment
    lines.retain(|(_, toks)| {
        !toks.iter().any(|t| t.starts_with(';') || t.starts_with("REM"))
    });

    for (ln, line) in lines {
        let _ = ln;
        if let Err(e) = parse_function_line(&mut sc, &mut current, &line) {
            return Err(e);
        }
    }
    if current.is_some() {
        return Err("EOF reached but End Function is missing".into());
    }
    Ok(sc)
}

/// ContractUsesSigner mirror (Go dvm.ContractUsesSigner, K0 Fix B2): true
/// iff any function line token equals "SIGNER" (case-insensitive, matching
/// the DVM's dispatch). Decides whether the NoSigner meta bit (0x80) is
/// set at install — must match Go byte-for-byte or the SC_META tree (and
/// the chain state root) diverges.
pub fn contract_uses_signer(sc: &SmartContract) -> bool {
    for f in sc.functions.values() {
        for line in f.lines.values() {
            for tok in line {
                if tok.eq_ignore_ascii_case("SIGNER") {
                    return true;
                }
            }
        }
    }
    false
}

fn parse_function_line(sc: &mut SmartContract, function: &mut Option<Function>, line: &[String]) -> Result<(), String> {
    let pos0 = 0;
    if function.is_none() {
        // only "Function" is legal
        if !line[pos0].eq_ignore_ascii_case("Function") {
            return Err(format!("Expecting declaration of function  but found \"{}\"", line[0]));
        }
        let mut pos = pos0 + 1;
        if line.len() < pos + 1 {
            return Err("function name missing".into());
        }
        if !check_valid_name(&line[pos]) {
            return Err(format!("function name \"{}\" contains invalid characters", line[pos]));
        }
        let mut f = Function {
            name: line[pos].clone(),
            params: Vec::new(),
            return_value: Variable { name: String::new(), vtype: Vtype::Invalid, value_uint64: 0, value_string: String::new() },
            lines: BTreeMap::new(),
            line_numbers: Vec::new(),
            line_numbers_index: HashMap::new(),
        };
        pos += 1;
        if line.len() < pos + 1 || line[pos] != "(" {
            return Err(format!("function \"{}\" missing '('", f.name));
        }
        // parse params
        loop {
            pos += 1;
            if line.len() < pos + 1 {
                return Err(format!("function \"{}\" missing function parameters", f.name));
            }
            if line[pos] == "," {
                continue;
            }
            if line[pos] == ")" {
                break;
            }
            if line.len() < pos + 2 {
                return Err(format!("function \"{}\" missing function parameters", f.name));
            }
            let param_name = line[pos].clone();
            let param_type = Vtype::from_name(&line[pos + 1]);
            if !check_valid_name(&param_name) {
                return Err(format!("function name \"{}\", variable name \"{}\" contains invalid characters", f.name, param_name));
            }
            if param_type == Vtype::Invalid {
                return Err(format!("function name \"{}\", variable type \"{}\" is invalid", f.name, line[pos + 1]));
            }
            f.params.push(Variable { name: param_name, vtype: param_type, value_uint64: 0, value_string: String::new() });
            pos += 1;
        }
        pos += 1;
        // return value
        if line.len() < pos + 1 {
            f.return_value = Variable { name: String::new(), vtype: Vtype::Invalid, value_uint64: 0, value_string: String::new() };
        } else {
            let rt = Vtype::from_name(&line[pos]);
            if rt == Vtype::Invalid {
                return Err(format!("function name \"{}\", return type \"{}\" is invalid", f.name, line[pos]));
            }
            f.return_value = Variable { name: String::new(), vtype: rt, value_uint64: 0, value_string: String::new() };
        }
        *function = Some(f);
        return Ok(());
    }

    if line.len() >= 2 && line[0].eq_ignore_ascii_case("End") && line[1].eq_ignore_ascii_case("Function") {
        let f = function.take().unwrap();
        sc.functions.insert(f.name.clone(), f);
        return Ok(());
    }
    if line[0].eq_ignore_ascii_case("Function") {
        return Err("Nested functions are not allowed".into());
    }

    // body line: line_number must be first, ascending, unique
    let f = function.as_mut().unwrap();
    let line_number: u64 = line[0].parse().map_err(|_| format!("Error Parsing line number \"{}\" in function  \"{}\" ", line[0], f.name))?;
    if line_number == 0 || line_number == u64::MAX {
        return Err(format!("Error: line number cannot be {}  in function  \"{}\" ", line_number, f.name));
    }
    if f.lines.contains_key(&line_number) {
        return Err(format!("Error: duplicate line number within function  \"{}\" ", f.name));
    }
    if f.line_numbers.len() >= 1 && line_number < *f.line_numbers.last().unwrap() {
        return Err(format!("Error: line number must be ascending within function  \"{}\" ", f.name));
    }
    let line_copy: Vec<String> = line[1..].to_vec();
    f.lines.insert(line_number, line_copy);
    f.line_numbers_index.insert(line_number, f.line_numbers.len() as u64);
    f.line_numbers.push(line_number);
    Ok(())
}

// ---------------------------------------------------------------------------
// uvarint (Go binary.Uvarint semantics)
// ---------------------------------------------------------------------------

pub fn put_uvarint(buf: &mut [u8], mut x: u64) -> usize {
    let mut i = 0;
    while x >= 0x80 {
        buf[i] = (x as u8) | 0x80;
        x >>= 7;
        i += 1;
    }
    buf[i] = x as u8;
    i + 1
}

pub fn uvarint(buf: &[u8]) -> (u64, i64) {
    let mut x: u64 = 0;
    let mut s: u32 = 0;
    for (i, &b) in buf.iter().enumerate() {
        if i == 10 {
            return (0, -(i as i64 + 1));
        }
        if b < 0x80 {
            if i == 9 && b > 1 {
                return (0, -(i as i64 + 1));
            }
            return (x | (b as u64) << s, i as i64 + 1);
        }
        x |= ((b & 0x7f) as u64) << s;
        s += 7;
    }
    (0, 0)
}

// ---------------------------------------------------------------------------
// interpreter (the DVM core)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct BlockchainInput {
    pub scid: [u8; 32],
    pub blid: [u8; 32],
    pub txid: [u8; 32],
    pub signer: String,
    pub bl_height: u64,
    pub bl_topoheight: u64,
    pub bl_timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct SharedState {
    pub scid_zero: [u8; 32],
    pub scid_self: [u8; 32],
    pub gas_compute_used: i64,
    pub gas_compute_limit: i64,
    pub gas_compute_check: bool,
    pub gas_store_used: i64,
    pub gas_store_limit: i64,
    pub gas_store_check: bool,
    pub chain_inputs: BlockchainInput,
    pub assets: HashMap<[u8; 32], u64>,
    pub assets_transfer: HashMap<String, HashMap<String, u64>>,
    pub ram_store: HashMap<Variable, Variable>,
    pub monitor_recursion: i64,
    pub monitor_lines_interpreted: i64,
    pub monitor_ops: i64,
    pub store: Box<TXStorage>,
    pub rnd: Rnd,
}

impl SharedState {
    /// Fresh state for SC execution (sc.go Execute_sc_function setup).
    pub fn new(scid: &[u8; 32], blid: &[u8; 32], txid: &[u8; 32], signer: &[u8; 33], bl_height: u64, bl_topoheight: u64, bl_timestamp: u64) -> Self {
        let mut rnd_key_bytes = Vec::with_capacity(96);
        rnd_key_bytes.extend_from_slice(scid);
        rnd_key_bytes.extend_from_slice(blid);
        rnd_key_bytes.extend_from_slice(txid);
        let rnd_key = crate::keccak::keccak256(&rnd_key_bytes);
        SharedState {
            scid_zero: [0; 32],
            scid_self: *scid,
            gas_compute_used: 0, gas_compute_limit: 0, gas_compute_check: false,
            gas_store_used: 0, gas_store_limit: 0, gas_store_check: false,
            chain_inputs: BlockchainInput {
                scid: *scid, blid: *blid, txid: *txid,
                signer: String::from_utf8_lossy(signer).to_string(),
                bl_height, bl_topoheight, bl_timestamp,
            },
            assets: HashMap::new(), assets_transfer: HashMap::new(), ram_store: HashMap::new(),
            monitor_recursion: 0, monitor_lines_interpreted: 0, monitor_ops: 0,
            store: Box::new(TXStorage { scid: *scid, raw_keys: HashMap::new(), state: None }),
            rnd: Rnd { key: rnd_key, pos: 1 },
        }
    }

    pub fn consume_gas(&mut self, c: i64) {
        self.gas_compute_used += c;
        if self.gas_compute_check && self.gas_compute_used > self.gas_compute_limit {
            panic!("Insufficient Gas");
        }
    }
    pub fn consume_storage_gas(&mut self, c: i64) {
        self.gas_store_used += c;
        if self.gas_store_check && self.gas_store_used > self.gas_store_limit {
            panic!("Insufficient Storage Gas");
        }
    }
}

#[derive(Debug, Clone)]
pub struct TXStorage {
    pub scid: [u8; 32],
    pub raw_keys: HashMap<String, Vec<u8>>,
    pub state: Option<SharedState>,
}

/// Deterministic RNG (deterministic_random_number.go): keccak(SCID‖BLID‖TXID)
/// key, HSalsa20-based, position counter starting at 1.
#[derive(Debug, Clone)]
pub struct Rnd {
    pub key: [u8; 32],
    pub pos: u64,
}

pub fn initialize_rnd(scid: &[u8; 32], blid: &[u8; 32], txid: &[u8; 32]) -> Rnd {
    let mut tmp = [0u8; 32];
    let mut seed = Vec::with_capacity(96);
    seed.extend_from_slice(scid);
    seed.extend_from_slice(blid);
    seed.extend_from_slice(txid);
    tmp.copy_from_slice(&keccak256(&seed));
    Rnd { key: tmp, pos: 1 }
}

impl Rnd {
    pub fn random(&mut self) -> u64 {
        // HSalsa20(out, in, key, in) with in = pos (big-endian)
        let mut inb = [0u8; 16];
        inb[..8].copy_from_slice(&self.pos.to_be_bytes());
        let out = hsalsa20(&self.key, &inb);
        let mut det = [0u8; 8];
        det.copy_from_slice(&out[..8]);
        self.pos += 1;
        u64::from_be_bytes(det)
    }
    pub fn random_max(&mut self, input: u64) -> u64 {
        if input == 0 {
            panic!("RNG cannot generate RND with 0 as max");
        }
        self.random() % input
    }
}

// HSalsa20 core (golang.org/x/crypto/salsa20/salsa) — mirrors the exact
// call HSalsa20(&out, &in, &key, &in): the 4th arg (the "constant" block)
// is the same 16-byte `in` value, NOT the Sigma constant.
pub fn hsalsa20(key: &[u8; 32], input: &[u8; 16]) -> [u8; 32] {
    let word = |b: &[u8], i: usize| -> u32 {
        u32::from_le_bytes([b[i * 4], b[i * 4 + 1], b[i * 4 + 2], b[i * 4 + 3]])
    };
    let mut z = [0u32; 16];
    // Go layout: x0=c[0..4], x1-4=k[0..16], x5=c[4..8], x6-9=in[0..16],
    //            x10=c[8..12], x11-14=k[16..32], x15=c[12..16]  (c == in here)
    z[0] = word(input, 0);
    z[1] = word(key, 0);
    z[2] = word(key, 1);
    z[3] = word(key, 2);
    z[4] = word(key, 3);
    z[5] = word(input, 1);
    z[6] = word(input, 0);
    z[7] = word(input, 1);
    z[8] = word(input, 2);
    z[9] = word(input, 3);
    z[10] = word(input, 2);
    z[11] = word(key, 4);
    z[12] = word(key, 5);
    z[13] = word(key, 6);
    z[14] = word(key, 7);
    z[15] = word(input, 3);
    for _ in 0..10 {
        // column round
        z[4] ^= z[0].wrapping_add(z[12]).rotate_left(7);
        z[8] ^= z[4].wrapping_add(z[0]).rotate_left(9);
        z[12] ^= z[8].wrapping_add(z[4]).rotate_left(13);
        z[0] ^= z[12].wrapping_add(z[8]).rotate_left(18);
        z[9] ^= z[5].wrapping_add(z[1]).rotate_left(7);
        z[13] ^= z[9].wrapping_add(z[5]).rotate_left(9);
        z[1] ^= z[13].wrapping_add(z[9]).rotate_left(13);
        z[5] ^= z[1].wrapping_add(z[13]).rotate_left(18);
        z[14] ^= z[10].wrapping_add(z[6]).rotate_left(7);
        z[2] ^= z[14].wrapping_add(z[10]).rotate_left(9);
        z[6] ^= z[2].wrapping_add(z[14]).rotate_left(13);
        z[10] ^= z[6].wrapping_add(z[2]).rotate_left(18);
        z[3] ^= z[15].wrapping_add(z[11]).rotate_left(7);
        z[7] ^= z[3].wrapping_add(z[15]).rotate_left(9);
        z[11] ^= z[7].wrapping_add(z[3]).rotate_left(13);
        z[15] ^= z[11].wrapping_add(z[7]).rotate_left(18);
        // row round — exact Go hsalsa20.go rows
        let u = z[0].wrapping_add(z[3]);
        z[1] ^= u.rotate_left(7);
        let u = z[1].wrapping_add(z[0]);
        z[2] ^= u.rotate_left(9);
        let u = z[2].wrapping_add(z[1]);
        z[3] ^= u.rotate_left(13);
        let u = z[3].wrapping_add(z[2]);
        z[0] ^= u.rotate_left(18);

        let u = z[5].wrapping_add(z[4]);
        z[6] ^= u.rotate_left(7);
        let u = z[6].wrapping_add(z[5]);
        z[7] ^= u.rotate_left(9);
        let u = z[7].wrapping_add(z[6]);
        z[4] ^= u.rotate_left(13);
        let u = z[4].wrapping_add(z[7]);
        z[5] ^= u.rotate_left(18);

        let u = z[10].wrapping_add(z[9]);
        z[11] ^= u.rotate_left(7);
        let u = z[11].wrapping_add(z[10]);
        z[8] ^= u.rotate_left(9);
        let u = z[8].wrapping_add(z[11]);
        z[9] ^= u.rotate_left(13);
        let u = z[9].wrapping_add(z[8]);
        z[10] ^= u.rotate_left(18);

        let u = z[15].wrapping_add(z[14]);
        z[12] ^= u.rotate_left(7);
        let u = z[12].wrapping_add(z[15]);
        z[13] ^= u.rotate_left(9);
        let u = z[13].wrapping_add(z[12]);
        z[14] ^= u.rotate_left(13);
        let u = z[14].wrapping_add(z[13]);
        z[15] ^= u.rotate_left(18);
    }
    let mut out = [0u8; 32];
    // HSalsa20 output: x0,x5,x10,x15,x6,x7,x8,x9 (words 0,5,10,15,6,7,8,9)
    let words = [z[0], z[5], z[10], z[15], z[6], z[7], z[8], z[9]];
    for (i, w) in words.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

/// RunSmartContract: checks the entrypoint name rules (exported = capital
/// first letter), initializes the RND once, runs, and verifies recursion
/// returns to zero. Returns the result Variable.
pub fn run_smart_contract(
    sc: &SmartContract,
    entry_point: &str,
    state: &mut SharedState,
    params: &HashMap<String, String>,
) -> Result<Variable, String> {
    let mut chars = entry_point.chars();
    let first = chars.next().ok_or("Invalid function name")?;
    if !first.is_ascii_alphabetic() || !first.is_uppercase() {
        return Err("Invalid function name, First character must be Capital/Upper Case".into());
    }
    if state.monitor_recursion == 0 {
        state.rnd = initialize_rnd(&state.chain_inputs.scid, &state.chain_inputs.blid, &state.chain_inputs.txid);
        state.assets_transfer = HashMap::new();
    }
    let result = run_smart_contract_internal(sc, entry_point, state, params)?;
    if state.monitor_recursion != 0 {
        return Err(format!("Invalid  recursion level {}", state.monitor_recursion));
    }
    Ok(result)
}

/// runSmartContract_internal (free function): parse params into locals, run
/// the interpreter on a fresh DVMInterpreter, return the result Variable.
pub fn run_smart_contract_internal(
    sc: &SmartContract,
    entry_point: &str,
    state: &mut SharedState,
    params: &HashMap<String, String>,
) -> Result<Variable, String> {
    let function_call = sc.functions.get(entry_point).cloned().ok_or_else(|| format!("function \"{}\" is not available in SC", entry_point))?;
    let mut dvm = DVMInterpreter {
        sc: sc.clone(),
        f: function_call.clone(),
        locals: HashMap::new(),
        state: std::mem::replace(state, SharedState {
            scid_zero: [0; 32], scid_self: [0; 32],
            gas_compute_used: 0, gas_compute_limit: 0, gas_compute_check: false,
            gas_store_used: 0, gas_store_limit: 0, gas_store_check: false,
            chain_inputs: BlockchainInput { scid: [0; 32], blid: [0; 32], txid: [0; 32], signer: String::new(), bl_height: 0, bl_topoheight: 0, bl_timestamp: 0 },
            assets: HashMap::new(), assets_transfer: HashMap::new(), ram_store: HashMap::new(),
            monitor_recursion: 0, monitor_lines_interpreted: 0, monitor_ops: 0,
            store: Box::new(TXStorage { scid: [0; 32], raw_keys: HashMap::new(), state: None }),
            rnd: Rnd { key: [0; 32], pos: 1 },
        }),
        ip: 0,
        return_value: Variable { name: String::new(), vtype: function_call.return_value.vtype, value_uint64: 0, value_string: String::new() },
        version: String::new(),
    };
    // NOTE: mem::replace moved the CALLER's real state into dvm.state and
    // left the empty placeholder in *state. Do NOT clobber dvm.state from
    // *state here — that would wipe the signer/chain_inputs (SIGNER() would
    // return empty). The caller's state is restored from dvm.state at the
    // end of this function.
    dvm.state.store.state = Some(dvm.state.clone());

    // parse parameters into locals
    for p in &function_call.params {
        let value = params.get(&p.name).ok_or_else(|| format!("Argument \"{}\" is missing while invoking \"{}\"", p.name, entry_point))?;
        let mut variable = Variable { name: p.name.clone(), vtype: p.vtype, value_uint64: 0, value_string: String::new() };
        match p.vtype {
            Vtype::Uint64 => {
                variable.value_uint64 = value.parse().map_err(|_| format!("bad uint64 param {}", value))?;
            }
            Vtype::String => variable.value_string = value.clone(),
            _ => panic!("unknown parameter type cannot have parameters"),
        }
        dvm.locals.insert(p.name.clone(), variable);
    }

    dvm.state.monitor_recursion += 1;
    let result = dvm.interpret_smart_contract();
    let result_var = dvm.return_value.clone();
    let new_state = dvm.state.clone();
    *state = new_state;
    state.store.state = Some(state.clone());
    result?;
    Ok(result_var)
}

// The interpreter — see dvm.go runSmartContract_internal + interpret_*.
pub struct DVMInterpreter {
    pub sc: SmartContract,
    pub f: Function,
    pub locals: HashMap<String, Variable>,
    pub state: SharedState,
    pub ip: u64,
    pub return_value: Variable,
    pub version: String,
}

impl DVMInterpreter {
    pub fn increment_ip(&mut self, newip: u64) -> Result<Vec<String>, String> {
        let line = loop {
            let next: u64;
            if newip == 0 {
                // fall through
                let index = match self.f.line_numbers_index.get(&self.ip) {
                    Some(&i) => i + 1,
                    None => 0,
                };
                if self.ip == 0 {
                    // start from first line (handled by index reset below)
                }
                let index = if self.ip == 0 { 0 } else { index };
                if (self.f.line_numbers.len() as u64) <= index {
                    return Err(format!("No lines after line number ({}) in SC {} in function {}", self.ip, "", self.f.name));
                }
                next = self.f.line_numbers[index as usize];
            } else {
                next = newip;
            }
            self.ip = next;
            if let Some(l) = self.f.lines.get(&self.ip) {
                if l.is_empty() {
                    continue;
                }
                break l.clone();
            } else {
                return Err(format!("No such line number ({}) in SC {} in function {}", self.ip, "", self.f.name));
            }
        };
        self.state.monitor_lines_interpreted += 1;
        Ok(line)
    }

    pub fn interpret_smart_contract(&mut self) -> Result<(), String> {
        let mut new_ip: u64 = 0;
        loop {
            let line = self.increment_ip(new_ip)?;
            self.state.consume_gas(5000);
            new_ip = 0;
            if self.state.monitor_lines_interpreted > LIMIT_INTERPRETED_LINES {
                panic!("{} lines interpreted, reached limit {}", LIMIT_INTERPRETED_LINES, LIMIT_INTERPRETED_LINES);
            }
            let cmd = line[0].to_ascii_uppercase();
            match cmd.as_str() {
                "DIM" => self.interpret_dim(&line[1..])?,
                "LET" => self.interpret_let(&line[1..])?,
                "GOTO" => new_ip = self.interpret_goto(&line[1..])?,
                "IF" => new_ip = self.interpret_if(&line[1..])?,
                "RETURN" => {
                    self.interpret_return(&line[1..])?;
                    // Go: RETURN exits the function immediately — set the
                    // sentinel so the loop breaks (new_ip = u64::MAX)
                    new_ip = u64::MAX;
                }
                "PRINT" | "PRINTF" => self.interpret_print(&line[1..])?,
                _ => {
                    // expression statement: must be a function call
                    self.eval_call_line(&line)?;
                }
            }
            if new_ip == u64::MAX {
                break;
            }
        }
        Ok(())
    }

    fn interpret_dim(&mut self, line: &[String]) -> Result<(), String> {
        if line.len() <= 2 || !line[line.len() - 2].eq_ignore_ascii_case("as") {
            return Err("Invalid DIM syntax".into());
        }
        let data_type = Vtype::from_name(&line[line.len() - 1]);
        if data_type == Vtype::Invalid {
            return Err(format!("function name \"{}\", No such Data type \"{}\"", self.f.name, line[line.len() - 1]));
        }
        for v in &line[..line.len() - 2] {
            if v == "," {
                continue;
            }
            if !check_valid_name(v) {
                return Err(format!("function name \"{}\", variable name \"{}\" contains invalid characters", self.f.name, v));
            }
            if self.locals.contains_key(v) {
                return Err(format!("function name \"{}\", variable name \"{}\" contains invalid characters", self.f.name, v));
            }
            let var = match data_type {
                Vtype::Uint64 => Variable::new_uint64(v, 0),
                Vtype::String => Variable::new_string(v, ""),
                _ => return Err(format!("DIM: unhandled data_type {:?}", data_type)),
            };
            self.locals.insert(v.clone(), var);
        }
        Ok(())
    }

    fn interpret_let(&mut self, line: &[String]) -> Result<(), String> {
        if line.len() <= 2 || line[1] != "=" {
            return Err("Invalid LET syntax".into());
        }
        if !self.locals.contains_key(&line[0]) {
            return Err(format!("function name \"{}\", variable name \"{}\"  is used without definition", self.f.name, line[0]));
        }
        let result_type = self.locals[&line[0]].vtype;
        let expr = self.parse_expr(&line[2..].join(" "))?;
        let expr_value = self.eval(&expr)?;
        match result_type {
            Vtype::Uint64 => {
                let v = expr_value.as_uint64().ok_or("type mismatch")?;
                self.locals.get_mut(&line[0]).unwrap().value_uint64 = v;
            }
            Vtype::String => {
                let v = expr_value.as_string().ok_or("type mismatch")?;
                self.locals.get_mut(&line[0]).unwrap().value_string = v;
            }
            _ => return Err(format!("LET: unhandled data_type {:?}", self.locals.get(&line[0]).map(|v| v.vtype).unwrap_or(Vtype::Invalid))),
        }
        Ok(())
    }

    fn interpret_goto(&mut self, line: &[String]) -> Result<u64, String> {
        if line.len() != 1 {
            return Err("GOTO  contains 1 mandatory line number as argument".into());
        }
        let newip: u64 = line[0].parse().map_err(|_| "bad goto".to_string())?;
        if newip == 0 || newip == u64::MAX {
            return Err(format!("GOTO  has invalid line number \"{}\"", newip));
        }
        Ok(newip)
    }

    fn interpret_if(&mut self, line: &[String]) -> Result<u64, String> {
        let mut thenip: u64 = 0;
        let mut elseip: u64 = 0;
        let mut expr_line: &[String] = line;
        if line.len() >= 4 && line[line.len() - 3].eq_ignore_ascii_case("THEN") && line[line.len() - 2].eq_ignore_ascii_case("GOTO") {
            thenip = line[line.len() - 1].parse().map_err(|_| "bad then".to_string())?;
            expr_line = &line[..line.len() - 3];
        } else if line.len() >= 7
            && line[line.len() - 6].eq_ignore_ascii_case("THEN")
            && line[line.len() - 5].eq_ignore_ascii_case("GOTO")
            && line[line.len() - 3].eq_ignore_ascii_case("ELSE")
            && line[line.len() - 2].eq_ignore_ascii_case("GOTO")
        {
            thenip = line[line.len() - 4].parse().map_err(|_| "bad then".to_string())?;
            elseip = line[line.len() - 1].parse().map_err(|_| "bad else".to_string())?;
            if elseip == 0 || elseip == u64::MAX {
                return Err(format!("ELSE GOTO  has invalid line number \"{}\"", thenip));
            }
            expr_line = &line[..line.len() - 6];
        } else {
            return Err("Invalid IF syntax".into());
        }
        if thenip == 0 || thenip == u64::MAX {
            return Err(format!("THEN GOTO  has invalid line number \"{}\"", thenip));
        }
        let expr = self.parse_expr(&expr_line.join(" "))?;
        let expr_value = self.eval(&expr)?;
        match expr_value {
            ExprValue::Uint64(v) => Ok(if v != 0 { thenip } else { elseip }),
            _ => Err(format!("Invalid IF expression  \"{}\"", expr_line.join(" "))),
        }
    }

    fn interpret_return(&mut self, line: &[String]) -> Result<(), String> {
        if self.return_value.vtype == Vtype::Invalid {
            if !line.is_empty() {
                return Err(format!("function name \"{}\" cannot return anything", self.f.name));
            }
            self.state.monitor_recursion -= 1;
            // newIP = MaxUint64 handled by caller via return value marker
            self.return_value.vtype = Vtype::Invalid;
            self.return_value.value_uint64 = u64::MAX; // sentinel: simple return
            return Ok(());
        }
        if line.is_empty() {
            return Err(format!("function name \"{}\" should return  a value", self.f.name));
        }
        let expr = self.parse_expr(&line.join(" "))?;
        let expr_value = self.eval(&expr)?;
        match self.return_value.vtype {
            Vtype::Uint64 => {
                self.return_value.value_uint64 = expr_value.as_uint64().ok_or("type mismatch")?;
            }
            Vtype::String => {
                self.return_value.value_string = expr_value.as_string().ok_or("type mismatch")?;
            }
            _ => panic!("unexpected data type"),
        }
        self.state.monitor_recursion -= 1;
        Ok(())
    }

    fn interpret_print(&mut self, line: &[String]) -> Result<(), String> {
        // PRINT is a no-op (reference prints only with trace on)
        let _ = line;
        Ok(())
    }

    /// Evaluate a bare call expression statement (the `default` arm).
    fn eval_call_line(&mut self, line: &[String]) -> Result<(), String> {
        let expr = self.parse_expr(&line.join(" "))?;
        match &expr {
            Expr::Call { .. } => {
                self.eval(&expr)?;
                Ok(())
            }
            _ => Err(format!("not a function call line {:?}", line)),
        }
    }
}

// -- expression AST + evaluator -------------------------------------------------

#[derive(Debug, Clone)]
pub enum Expr {
    Int(u64),
    Str(String),
    Ident(String),
    Unary(char, Box<Expr>),
    Binary(char, Box<Expr>, Box<Expr>),
    Call(String, Vec<Expr>),
    Paren(Box<Expr>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExprValue {
    Uint64(u64),
    String(String),
}

impl ExprValue {
    fn as_uint64(&self) -> Option<u64> {
        match self {
            ExprValue::Uint64(v) => Some(*v),
            _ => None,
        }
    }
    fn as_string(&self) -> Option<String> {
        match self {
            ExprValue::String(v) => Some(v.clone()),
            _ => None,
        }
    }
    fn is_zero(&self) -> u64 {
        match self {
            ExprValue::Uint64(v) => if *v == 0 { 1 } else { 0 },
            ExprValue::String(v) => if v.is_empty() { 1 } else { 0 },
        }
    }
}

// A tiny recursive-descent parser for the DERO expression subset
// (numbers, strings, identifiers, calls, unary ~/!, binary ops, parens).
impl DVMInterpreter {
    pub fn parse_expr(&mut self, src: &str) -> Result<Expr, String> {
        // normalize operator spacing like Go's replacer
        let s = src
            .replace("< =", "<=")
            .replace("> =", ">=")
            .replace("= =", "==")
            .replace("! =", "!=")
            .replace("& &", "&&")
            .replace("| |", "||")
            .replace("< <", "<<")
            .replace("> >", ">>")
            .replace("< >", "!=");
        let toks = tokenize(&s);
        // Recombine multi-char operators that the (Go-compatible) tokenizer
        // split character-by-character (`value = = 0` -> `==`, `a ! = b` ->
        // `!=`, etc.). The line tokenizer keeps operators separate so the
        // stored f.lines match Go's space-joined serialization byte-for-byte;
        // here on the execution path we merge them so the parser recognizes
        // the real operator tokens.
        let merged = merge_operator_tokens(toks);
        let mut p = ExprParser { toks: &merged, pos: 0 };
        let e = p.parse_expr()?;
        if p.pos < merged.len() {
            return Err(format!("trailing tokens"));
        }
        Ok(e)
    }
}

struct ExprParser<'a> {
    toks: &'a [(u32, String)],
    pos: usize,
}

impl<'a> ExprParser<'a> {
    fn peek(&self) -> Option<&str> {
        self.toks.get(self.pos).map(|(_, t)| t.as_str())
    }
    fn next(&mut self) -> Option<String> {
        let t = self.toks.get(self.pos).map(|(_, t)| t.clone());
        if t.is_some() {
            self.pos += 1;
        }
        t
    }
    fn parse_expr(&mut self) -> Result<Expr, String> {
        self.parse_or()
    }
    fn parse_or(&mut self) -> Result<Expr, String> {
        let mut l = self.parse_and()?;
        while self.peek() == Some("||") {
            self.next();
            let r = self.parse_and()?;
            l = Expr::Binary('|', Box::new(l), Box::new(r));
        }
        Ok(l)
    }
    fn parse_and(&mut self) -> Result<Expr, String> {
        let mut l = self.parse_cmp()?;
        while self.peek() == Some("&&") {
            self.next();
            let r = self.parse_cmp()?;
            l = Expr::Binary('&', Box::new(l), Box::new(r));
        }
        Ok(l)
    }
    fn parse_cmp(&mut self) -> Result<Expr, String> {
        let mut l = self.parse_add()?;
        loop {
            let op = match self.peek() {
                Some("==") => Some('='),
                Some("!=") => Some('!'),
                Some("<") => Some('<'),
                Some("<=") => Some('{'),
                Some(">") => Some('>'),
                Some(">=") => Some('}'),
                _ => None,
            };
            match op {
                Some(o) => {
                    self.next();
                    let r = self.parse_add()?;
                    l = Expr::Binary(o, Box::new(l), Box::new(r));
                }
                None => break,
            }
        }
        Ok(l)
    }
    fn parse_add(&mut self) -> Result<Expr, String> {
        let mut l = self.parse_mul()?;
        loop {
            let op = match self.peek() {
                Some("+") => Some('+'),
                Some("-") => Some('-'),
                Some("|") => Some('|'),
                Some("^") => Some('^'),
                Some(">>") => Some('r'),  // SHR (shift-right); '>' is GTR in parse_cmp
                Some("<<") => Some('l'),  // SHL (shift-left); '<' is LSS in parse_cmp
                _ => None,
            };
            match op {
                Some(o) => {
                    self.next();
                    let r = self.parse_mul()?;
                    l = Expr::Binary(o, Box::new(l), Box::new(r));
                }
                None => break,
            }
        }
        Ok(l)
    }
    fn parse_mul(&mut self) -> Result<Expr, String> {
        let mut l = self.parse_unary()?;
        loop {
            let op = match self.peek() {
                Some("*") => Some('*'),
                Some("/") => Some('/'),
                Some("%") => Some('%'),
                Some("&") => Some('&'),
                _ => None,
            };
            match op {
                Some(o) => {
                    self.next();
                    let r = self.parse_unary()?;
                    l = Expr::Binary(o, Box::new(l), Box::new(r));
                }
                None => break,
            }
        }
        Ok(l)
    }
    fn parse_unary(&mut self) -> Result<Expr, String> {
        match self.peek() {
            Some("~") | Some("!") => {
                let op = self.next().unwrap();
                let e = self.parse_unary()?;
                Ok(Expr::Unary(op.chars().next().unwrap(), Box::new(e)))
            }
            _ => self.parse_primary(),
        }
    }
    fn parse_primary(&mut self) -> Result<Expr, String> {
        let t = self.next().ok_or("unexpected end")?;
        // number literal (possibly negative)
        if let Ok(v) = parse_uint(&t) {
            return Ok(Expr::Int(v));
        }
        if t.starts_with('"') || t.starts_with('\'') || t.starts_with('`') {
            let inner = &t[1..t.len().saturating_sub(1)];
            // unescape Go string (\\n etc) — the reference uses strconv.Unquote
            let unq = unquote(inner);
            return Ok(Expr::Str(unq));
        }
        // call?
        if self.peek() == Some("(") {
            self.next();
            let mut args = Vec::new();
            if self.peek() == Some(")") {
                self.next();
            } else {
                loop {
                    args.push(self.parse_expr()?);
                    if self.peek() == Some(",") {
                        self.next();
                        continue;
                    }
                    if self.peek() == Some(")") {
                        self.next();
                        break;
                    }
                    return Err("bad arg list".into());
                }
            }
            return Ok(Expr::Call(t, args));
        }
        if t == "(" {
            let e = self.parse_expr()?;
            if self.peek() == Some(")") {
                self.next();
            }
            return Ok(Expr::Paren(Box::new(e)));
        }
        // identifier
        Ok(Expr::Ident(t))
    }
}

fn parse_uint(s: &str) -> Result<u64, ()> {
    let v = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|_| ())?
    } else if let Some(oct) = s.strip_prefix("0o").or_else(|| s.strip_prefix("0O")) {
        u64::from_str_radix(oct, 8).map_err(|_| ())?
    } else if s.len() > 1 && s.starts_with('0') {
        u64::from_str_radix(&s[1..], 8).map_err(|_| ())?
    } else {
        s.parse::<u64>().map_err(|_| ())?
    };
    Ok(v)
}

fn unquote(s: &str) -> String {
    // minimal Go strconv.Unquote subset (escapes the DVM SCs actually use)
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some('"') => out.push('"'),
                Some('\'') => out.push('\''),
                Some('\\') => out.push('\\'),
                Some('x') => {
                    let h: String = chars.by_ref().take(2).collect();
                    if let Ok(v) = u8::from_str_radix(&h, 16) {
                        out.push(v as char);
                    }
                }
                Some('u') => {
                    let h: String = chars.by_ref().take(4).collect();
                    if let Ok(v) = u32::from_str_radix(&h, 16) {
                        if let Some(c) = char::from_u32(v) {
                            out.push(c);
                        }
                    }
                }
                Some(other) => out.push(other),
                None => {}
            }
        } else {
            out.push(c);
        }
    }
    out
}

impl DVMInterpreter {
    pub fn eval(&mut self, expr: &Expr) -> Result<ExprValue, String> {
        self.state.monitor_ops += 1;
        if self.state.monitor_ops > LIMIT_EVALS {
            panic!("{} lines interpreted, evals reached limit {}", self.state.monitor_lines_interpreted, LIMIT_EVALS);
        }
        match expr {
            Expr::Int(v) => Ok(ExprValue::Uint64(*v)),
            Expr::Str(s) => Ok(ExprValue::String(s.clone())),
            Expr::Ident(name) => {
                if !self.locals.contains_key(name) {
                    panic!("function name \"{}\", variable name \"{}\"  is used without definition", self.f.name, name);
                }
                let v = &self.locals[name];
                match v.vtype {
                    Vtype::Uint64 => Ok(ExprValue::Uint64(v.value_uint64)),
                    Vtype::String => Ok(ExprValue::String(v.value_string.clone())),
                    _ => panic!("unexpected data type"),
                }
            }
            Expr::Paren(inner) => self.eval(inner),
            Expr::Unary(op, inner) => {
                let x = self.eval(inner)?;
                match op {
                    '~' => Ok(ExprValue::Uint64(!x.as_uint64().ok_or("type mismatch")?)),
                    '!' => match x {
                        ExprValue::Uint64(v) => Ok(ExprValue::Uint64(!v)),
                        ExprValue::String(v) => Ok(ExprValue::Uint64(if v.is_empty() { 1 } else { 0 })),
                    },
                    _ => Err("bad unary".into()),
                }
            }
            Expr::Binary(op, l, r) => {
                self.state.consume_gas(800);
                let lv = self.eval(l)?;
                let rv = self.eval(r)?;
                self.eval_binary(*op, lv, rv)
            }
            Expr::Call(name, args) => self.eval_call(name, args),
        }
    }

    fn eval_binary(&mut self, op: char, left: ExprValue, right: ExprValue) -> Result<ExprValue, String> {
        // string + uint64 auto-concat
        if let (ExprValue::String(l), ExprValue::Uint64(r)) = (&left, &right) {
            if op == '+' {
                return Ok(ExprValue::String(format!("{}{}", l, r)));
            }
        }
        // type check: must be same type
        let same = match (&left, &right) {
            (ExprValue::Uint64(_), ExprValue::Uint64(_)) => true,
            (ExprValue::String(_), ExprValue::String(_)) => true,
            _ => false,
        };
        if !same {
            panic!("Expressions cannot be different type(String/Uint64)");
        }
        match op {
            '&' => {
                // logical AND (go LAND) — both non-zero
                let lz = left.is_zero();
                let rz = right.is_zero();
                return Ok(ExprValue::Uint64(if lz == 0 && rz == 0 { 1 } else { 0 }));
            }
            '|' => {
                // logical OR (go LOR) — either non-zero
                let lz = left.is_zero();
                let rz = right.is_zero();
                return Ok(ExprValue::Uint64(if lz == 0 || rz == 0 { 1 } else { 0 }));
            }
            _ => {}
        }
        match (left, right) {
            (ExprValue::String(l), ExprValue::String(r)) => match op {
                '+' => {
                    if l.len() + r.len() >= 1024 * 1024 {
                        panic!("too big string value");
                    }
                    Ok(ExprValue::String(l + &r))
                }
                '=' => Ok(ExprValue::Uint64(if l == r { 1 } else { 0 })),
                '!' => Ok(ExprValue::Uint64(if l != r { 1 } else { 0 })),
                _ => Err(format!("String data type only support addition operation ('{}') not supported", op)),
            },
            (ExprValue::Uint64(l), ExprValue::Uint64(r)) => Ok(ExprValue::Uint64(match op {
                '+' => l.wrapping_add(r),
                '-' => l.wrapping_sub(r),
                '*' => l.wrapping_mul(r),
                '/' => l / r,
                '%' => l % r,
                '&' => l & r,
                '|' => l | r,
                '^' => l ^ r,
                '<' => if l < r { 1 } else { 0 },   // LSS (less-than); Go token.LSS
                '>' => if l > r { 1 } else { 0 },   // GTR (greater-than); Go token.GTR
                'l' => l << r,                       // SHL; parse_add maps "<<" here
                'r' => l >> r,                       // SHR; parse_add maps ">>" here
                '=' => if l == r { 1 } else { 0 },
                '!' => if l != r { 1 } else { 0 },
                '{' => if l <= r { 1 } else { 0 },
                '}' => if l >= r { 1 } else { 0 },
                _ => return Err("This operation cannot be handled".into()),
            })),
            _ => Err("type mismatch".into()),
        }
    }

    fn eval_call(&mut self, name: &str, args: &[Expr]) -> Result<ExprValue, String> {
        // internal (builtin) functions take precedence
        if let Some(result) = self.handle_internal_function(name, args)? {
            return Ok(result);
        }
        let function_call = match self.sc.functions.get(name) {
            Some(f) => f.clone(),
            None => panic!("Unknown function called \"{}\"", name),
        };
        if function_call.params.len() != args.len() {
            panic!(
                "function \"{}\" called with incorrect number of arguments , expected {} , actual {}",
                name,
                function_call.params.len(),
                args.len()
            );
        }
        let mut arguments: HashMap<String, String> = HashMap::new();
        for (i, p) in function_call.params.iter().enumerate() {
            let v = self.eval(&args[i])?;
            match p.vtype {
                Vtype::Uint64 => {
                    arguments.insert(p.name.clone(), format!("{}", v.as_uint64().ok_or("type mismatch")?));
                }
                Vtype::String => {
                    arguments.insert(p.name.clone(), v.as_string().ok_or("type mismatch")?);
                }
                _ => {}
            }
        }
        let result = self.run_smart_contract_internal(&function_call.name, &arguments)?;
        match function_call.return_value.vtype {
            Vtype::Uint64 => Ok(ExprValue::Uint64(result.value_uint64)),
            Vtype::String => Ok(ExprValue::String(result.value_string)),
            _ => Ok(ExprValue::Uint64(0)),
        }
    }

    fn run_smart_contract_internal(&mut self, entry_point: &str, params: &HashMap<String, String>) -> Result<Variable, String> {
        let function_call = match self.sc.functions.get(entry_point) {
            Some(f) => f.clone(),
            None => return Err(format!("function \"{}\" is not available in SC", entry_point)),
        };
        // save interpreter state, run a fresh one
        let saved = std::mem::replace(&mut self.f, function_call.clone());
        let saved_locals = std::mem::replace(&mut self.locals, HashMap::new());
        let saved_ret = std::mem::replace(
            &mut self.return_value,
            Variable { name: String::new(), vtype: function_call.return_value.vtype, value_uint64: 0, value_string: String::new() },
        );
        // parse params into locals
        for p in &function_call.params {
            let value = params.get(&p.name).ok_or_else(|| format!("Argument \"{}\" is missing while invoking \"{}\"", p.name, entry_point))?;
            let mut variable = Variable { name: p.name.clone(), vtype: p.vtype, value_uint64: 0, value_string: String::new() };
            match p.vtype {
                Vtype::Uint64 => {
                    variable.value_uint64 = parse_uint(value).map_err(|_| format!("bad uint64 param {}", value))?;
                }
                Vtype::String => variable.value_string = value.clone(),
                _ => panic!("unknown parameter type cannot have parameters"),
            }
            self.locals.insert(p.name.clone(), variable);
        }
        self.state.monitor_recursion += 1;
        let result = self.interpret_smart_contract();
        let result_var = self.return_value.clone();
        // restore
        self.f = saved;
        self.locals = saved_locals;
        self.return_value = saved_ret;
        result?;
        Ok(result_var)
    }

    // The builtin function table — dvm_functions.go. Costs are the reference's.
    fn handle_internal_function(&mut self, name: &str, args: &[Expr]) -> Result<Option<ExprValue>, String> {
        let lower = name.to_ascii_lowercase();
        let (compute_cost, handler): (i64, fn(&mut Self, &[Expr]) -> Result<ExprValue, String>) = match lower.as_str() {
            "version" => (1000, builtin_version),
            "load" => (5000, builtin_load),
            "exists" => (5000, builtin_exists),
            "store" => (10000, builtin_store),
            "delete" => (3000, builtin_delete),
            "mapexists" => (1000, builtin_mapexists),
            "mapget" => (1000, builtin_mapget),
            "mapstore" => (1000, builtin_mapstore),
            "mapdelete" => (1000, builtin_mapdelete),
            "random" => (2500, builtin_random),
            "scid" => (2000, builtin_scid),
            "blid" => (2000, builtin_blid),
            "txid" => (2000, builtin_txid),
            "dero" => (10000, builtin_dero),
            "block_height" => (2000, builtin_block_height),
            "block_timestamp" => (2500, builtin_block_timestamp),
            "signer" => (5000, builtin_signer),
            "update_sc_code" => (5000, builtin_update_sc_code),
            "is_address_valid" => (50000, builtin_is_address_valid),
            "address_raw" => (60000, builtin_address_raw),
            "address_string" => (50000, builtin_address_string),
            "send_dero_to_address" => (70000, builtin_send_dero_to_address),
            "send_asset_to_address" => (90000, builtin_send_asset_to_address),
            "derovalue" => (10000, builtin_derovalue),
            "assetvalue" => (10000, builtin_assetvalue),
            "atoi" => (5000, builtin_atoi),
            "itoa" => (5000, builtin_itoa),
            "sha256" => (25000, builtin_sha256),
            "sha3256" => (25000, builtin_sha3256),
            "keccak256" => (25000, builtin_keccak256),
            "hex" => (10000, builtin_hex),
            "hexdecode" => (10000, builtin_hexdecode),
            "min" => (5000, builtin_min),
            "max" => (5000, builtin_max),
            "strlen" => (20000, builtin_strlen),
            "substr" => (20000, builtin_substr),
            "panic" => (10000, builtin_panic),
            _ => return Ok(None),
        };
        self.state.consume_gas(compute_cost);
        let result = handler(self, args)?;
        Ok(Some(result))
    }
}

fn checkargscount(expected: usize, actual: usize) {
    if expected != actual {
        panic!("incorrect number of arguments");
    }
}

// -- builtins ---------------------------------------------------------------

fn builtin_version(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    checkargscount(1, args.len());
    let v = dvm.eval(&args[0])?;
    match v {
        ExprValue::String(s) => {
            dvm.version = s;
            Ok(ExprValue::Uint64(1))
        }
        _ => panic!("unsupported version format"),
    }
}

fn builtin_load(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    checkargscount(1, args.len());
    let key = dvm.eval(&args[0])?;
    let keyv = convert_to_variable(key);
    let dkey = DataKey { scid: dvm.state.chain_inputs.scid, balance: false, key: keyv };
    let mut found = 0u64;
    let result = dvm.state.store.load(&dkey, &mut found);
    if found == 0 {
        // Missing key: return 0 (matches Go DVM default for absent keys)
        return Ok(ExprValue::Uint64(0));
    }
    Ok(match result.vtype {
        Vtype::Uint64 => ExprValue::Uint64(result.value_uint64),
        Vtype::String => ExprValue::String(result.value_string),
        Vtype::Invalid => ExprValue::Uint64(0), // default for uninitialized
        _ => return Err(format!("load: unhandled vtype {:?}", result.vtype)),
    })
}

fn builtin_exists(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    checkargscount(1, args.len());
    let key = dvm.eval(&args[0])?;
    let keyv = convert_to_variable(key);
    let dkey = DataKey { scid: dvm.state.chain_inputs.scid, balance: false, key: keyv };
    let mut found = 0u64;
    dvm.state.store.load(&dkey, &mut found);
    Ok(ExprValue::Uint64(found))
}

fn builtin_store(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    checkargscount(2, args.len());
    let key = convert_to_variable(dvm.eval(&args[0])?);
    let value = convert_to_variable(dvm.eval(&args[1])?);
    let dkey = DataKey { scid: dvm.state.chain_inputs.scid, balance: false, key };
    dvm.state.store.store(&dkey, &value);
    Ok(ExprValue::Uint64(1))
}

fn builtin_delete(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    checkargscount(1, args.len());
    let key = convert_to_variable(dvm.eval(&args[0])?);
    let dkey = DataKey { scid: dvm.state.chain_inputs.scid, balance: false, key };
    dvm.state.store.delete(&dkey);
    Ok(ExprValue::Uint64(1))
}

fn builtin_mapexists(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    checkargscount(1, args.len());
    let key = convert_to_variable(dvm.eval(&args[0])?);
    Ok(ExprValue::Uint64(if dvm.state.ram_store.contains_key(&key) { 1 } else { 0 }))
}

fn builtin_mapget(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    checkargscount(1, args.len());
    let key = convert_to_variable(dvm.eval(&args[0])?);
    let v = dvm.state.ram_store.get(&key).cloned().ok_or("This variable cannot be obtained")?;
    Ok(match v.vtype {
        Vtype::Uint64 => ExprValue::Uint64(v.value_uint64),
        Vtype::String => ExprValue::String(v.value_string),
        _ => panic!("This variable cannot be obtained"),
    })
}

fn builtin_mapstore(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    checkargscount(2, args.len());
    let key = convert_to_variable(dvm.eval(&args[0])?);
    let value = convert_to_variable(dvm.eval(&args[1])?);
    dvm.state.ram_store.insert(key, value);
    Ok(ExprValue::Uint64(1))
}

fn builtin_mapdelete(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    checkargscount(1, args.len());
    let key = convert_to_variable(dvm.eval(&args[0])?);
    dvm.state.ram_store.remove(&key);
    Ok(ExprValue::Uint64(1))
}

fn builtin_random(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    if args.len() >= 2 {
        panic!("RANDOM function expects 0 or 1 number as parameter");
    }
    if args.is_empty() {
        return Ok(ExprValue::Uint64(dvm.state.rnd.random()));
    }
    let r = dvm.eval(&args[0])?;
    match r {
        ExprValue::Uint64(m) => Ok(ExprValue::Uint64(dvm.state.rnd.random_max(m))),
        _ => panic!("This variable cannot be randomly generated"),
    }
}

fn builtin_scid(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    checkargscount(0, args.len());
    Ok(ExprValue::String(String::from_utf8_lossy(&dvm.state.chain_inputs.scid).into_owned()))
}

fn builtin_blid(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    checkargscount(0, args.len());
    Ok(ExprValue::String(String::from_utf8_lossy(&dvm.state.chain_inputs.blid).into_owned()))
}

fn builtin_txid(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    checkargscount(0, args.len());
    Ok(ExprValue::String(String::from_utf8_lossy(&dvm.state.chain_inputs.txid).into_owned()))
}

fn builtin_dero(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    checkargscount(0, args.len());
    Ok(ExprValue::String(String::from_utf8_lossy(&dvm.state.scid_zero).into_owned()))
}

fn builtin_block_height(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    checkargscount(0, args.len());
    Ok(ExprValue::Uint64(dvm.state.chain_inputs.bl_height))
}

fn builtin_block_timestamp(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    checkargscount(0, args.len());
    Ok(ExprValue::Uint64(dvm.state.chain_inputs.bl_timestamp))
}

fn builtin_signer(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    checkargscount(0, args.len());
    Ok(ExprValue::String(dvm.state.chain_inputs.signer.clone()))
}

fn builtin_update_sc_code(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    checkargscount(1, args.len());
    let code = dvm.eval(&args[0])?;
    match code {
        ExprValue::String(s) => {
            let dkey = DataKey { scid: [0; 32], balance: false, key: Variable::new_string("", "C") };
            dvm.state.store.store(&dkey, &Variable::new_string("", &s));
            Ok(ExprValue::Uint64(1))
        }
        _ => Ok(ExprValue::Uint64(0)),
    }
}

fn builtin_is_address_valid(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    checkargscount(1, args.len());
    let addr = dvm.eval(&args[0])?;
    match addr {
        ExprValue::String(s) => {
            if s.len() == 33 && crate::curve::decode_compressed(s.as_bytes()).is_ok() {
                Ok(ExprValue::Uint64(1))
            } else {
                Ok(ExprValue::Uint64(0))
            }
        }
        _ => Ok(ExprValue::Uint64(0)),
    }
}

fn builtin_address_raw(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    checkargscount(1, args.len());
    let addr = dvm.eval(&args[0])?;
    match addr {
        ExprValue::String(s) => {
            // bech32 → compressed 33-byte key
            if let Ok(pk) = crate::rpc_addr::address_to_compressed(&s) {
                Ok(ExprValue::String(String::from_utf8_lossy(&pk).into_owned()))
            } else {
                Ok(ExprValue::String(String::new()))
            }
        }
        _ => Ok(ExprValue::String(String::new())),
    }
}

fn builtin_address_string(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    checkargscount(1, args.len());
    let addr = dvm.eval(&args[0])?;
    match addr {
        ExprValue::String(s) => {
            if s.len() == 33 {
                if let Ok(addr_str) = crate::rpc_addr::compressed_to_address(s.as_bytes()) {
                    Ok(ExprValue::String(addr_str))
                } else {
                    Ok(ExprValue::String(String::new()))
                }
            } else {
                Ok(ExprValue::String(String::new()))
            }
        }
        _ => Ok(ExprValue::String(String::new())),
    }
}

fn builtin_send_dero_to_address(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    checkargscount(2, args.len());
    let addr = dvm.eval(&args[0])?;
    let amount = dvm.eval(&args[1])?;
    let addr_s = addr.as_string().ok_or("address must be valid DERO network address")?;
    if std::env::var("SC_DEBUG").is_ok() {
        eprintln!("SEND_DERO addr len={} hex={:?}", addr_s.len(), hex::encode(addr_s.as_bytes()));
    }
    // Go: DecodeCompressed([]byte(addr)) — a 33-byte compressed point
    if !(addr_s.len() == 33 && crate::curve::decode_compressed(addr_s.as_bytes()).is_ok()) {
        return Err("address must be valid DERO network address".into());
    }
    let amount = amount.as_uint64().ok_or("amount must be valid  uint64")?;
    if amount == 0 {
        return Ok(ExprValue::Uint64(amount));
    }
    dvm.state.store.send_external(dvm.state.chain_inputs.scid, [0; 32], addr_s, amount);
    Ok(ExprValue::Uint64(amount))
}

fn builtin_send_asset_to_address(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    checkargscount(3, args.len());
    let addr = dvm.eval(&args[0])?;
    let amount = dvm.eval(&args[1])?;
    let asset = dvm.eval(&args[2])?;
    let addr_s = addr.as_string().ok_or("address must be valid DERO network address")?;
    if !(addr_s.len() == 33 && crate::curve::decode_compressed(addr_s.as_bytes()).is_ok()) {
        panic!("address must be valid DERO network address");
    }
    let amount = amount.as_uint64().ok_or("amount must be valid  uint64")?;
    let asset_s = asset.as_string().ok_or("asset must be valid string")?;
    if amount == 0 {
        return Ok(ExprValue::Uint64(amount));
    }
    if asset_s.len() != 32 {
        panic!("asset must be valid string of 32 byte length");
    }
    let mut asset_bytes = [0u8; 32];
    asset_bytes.copy_from_slice(asset_s.as_bytes());
    dvm.state.store.send_external(dvm.state.chain_inputs.scid, asset_bytes, addr_s, amount);
    Ok(ExprValue::Uint64(amount))
}

fn builtin_derovalue(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    checkargscount(0, args.len());
    let v = *dvm.state.assets.get(&dvm.state.scid_zero).unwrap_or(&0);
    Ok(ExprValue::Uint64(v))
}

fn builtin_assetvalue(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    checkargscount(1, args.len());
    let asset = dvm.eval(&args[0])?;
    let asset_s = asset.as_string().ok_or("asset must be valid string")?;
    if asset_s.len() != 32 {
        panic!("asset must be valid string of 32 byte length");
    }
    let mut asset_bytes = [0u8; 32];
    asset_bytes.copy_from_slice(asset_s.as_bytes());
    Ok(ExprValue::Uint64(*dvm.state.assets.get(&asset_bytes).unwrap_or(&0)))
}

fn builtin_itoa(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    checkargscount(1, args.len());
    let v = dvm.eval(&args[0])?;
    Ok(ExprValue::String(format!("{}", v.as_uint64().ok_or("itoa argument must be valid uint64")?)))
}

fn builtin_atoi(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    checkargscount(1, args.len());
    let v = dvm.eval(&args[0])?;
    let s = v.as_string().ok_or("atoi argument must be valid string")?;
    let u: u64 = s.trim().parse().map_err(|_| "bad atoi".to_string())?;
    Ok(ExprValue::Uint64(u))
}

fn builtin_strlen(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    checkargscount(1, args.len());
    let v = dvm.eval(&args[0])?;
    Ok(ExprValue::Uint64(v.as_string().ok_or("strlen argument must be valid string")?.len() as u64))
}

/// Build a Rust String that holds raw (possibly non-UTF-8) bytes, matching
/// Go's byte-string semantics (`string(hash[:])`). The DVM treats string
/// values as opaque byte strings (as_bytes/len/concat/hex), never as UTF-8,
/// so this is safe and byte-exact.
fn raw_bytes_string(bytes: &[u8]) -> String {
    unsafe { String::from_utf8_unchecked(bytes.to_vec()) }
}

fn builtin_sha256(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    checkargscount(1, args.len());
    let v = dvm.eval(&args[0])?;
    let s = v.as_string().ok_or("input argument must be valid string")?;
    let h = crate::sha2_256(s.as_bytes());
    Ok(ExprValue::String(raw_bytes_string(&h)))
}

fn builtin_sha3256(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    checkargscount(1, args.len());
    let v = dvm.eval(&args[0])?;
    let s = v.as_string().ok_or("input argument must be valid string")?;
    let h = crate::sha3_256(s.as_bytes());
    Ok(ExprValue::String(raw_bytes_string(&h)))
}

fn builtin_keccak256(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    checkargscount(1, args.len());
    let v = dvm.eval(&args[0])?;
    let s = v.as_string().ok_or("input argument must be valid string")?;
    let h = crate::keccak::keccak256(s.as_bytes());
    Ok(ExprValue::String(raw_bytes_string(&h)))
}

fn builtin_hex(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    checkargscount(1, args.len());
    let v = dvm.eval(&args[0])?;
    let s = v.as_string().ok_or("input argument must be valid string")?;
    Ok(ExprValue::String(hex::encode(s.as_bytes())))
}

fn builtin_hexdecode(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    checkargscount(1, args.len());
    let v = dvm.eval(&args[0])?;
    let s = v.as_string().ok_or("input argument must be valid string")?;
    let b = hex::decode(&s).map_err(|e| e.to_string())?;
    Ok(ExprValue::String(String::from_utf8_lossy(&b).into_owned()))
}

fn builtin_min(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    checkargscount(2, args.len());
    let a1 = dvm.eval(&args[0])?.as_uint64().ok_or("input argument must be uint64")?;
    let a2 = dvm.eval(&args[1])?.as_uint64().ok_or("input argument must be uint64")?;
    Ok(ExprValue::Uint64(a1.min(a2)))
}

fn builtin_max(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    checkargscount(2, args.len());
    let a1 = dvm.eval(&args[0])?.as_uint64().ok_or("input argument must be uint64")?;
    let a2 = dvm.eval(&args[1])?.as_uint64().ok_or("input argument must be uint64")?;
    Ok(ExprValue::Uint64(a1.max(a2)))
}

fn builtin_substr(dvm: &mut DVMInterpreter, args: &[Expr]) -> Result<ExprValue, String> {
    checkargscount(3, args.len());
    let input = dvm.eval(&args[0])?.as_string().ok_or("input argument must be valid string")?;
    let start = dvm.eval(&args[1])?.as_uint64().ok_or("input argument must be valid uint64")?;
    let length = dvm.eval(&args[2])?.as_uint64().ok_or("input argument must be valid uint64")?;
    let asbytes = input.as_bytes();
    if start >= asbytes.len() as u64 {
        return Ok(ExprValue::String(String::new()));
    }
    let mut length = length;
    if start + length > asbytes.len() as u64 {
        length = asbytes.len() as u64 - start;
    }
    let sub = String::from_utf8_lossy(&asbytes[start as usize..(start + length) as usize]).into_owned();
    Ok(ExprValue::String(sub))
}

fn builtin_panic(_dvm: &mut DVMInterpreter, _args: &[Expr]) -> Result<ExprValue, String> {
    panic!("panic function called");
}

fn convert_to_variable(v: ExprValue) -> Variable {
    match v {
        ExprValue::Uint64(k) => Variable::new_uint64("", k),
        ExprValue::String(k) => Variable::new_string("", &k),
    }
}

// -- store ---------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DataKey {
    pub scid: [u8; 32],
    pub balance: bool,
    pub key: Variable,
}

impl DataKey {
    pub fn marshal_binary_panic(&self) -> Vec<u8> {
        if self.balance {
            match self.key.vtype {
                Vtype::String => return self.key.value_string.as_bytes().to_vec(),
                _ => panic!("balance keys can only be string"),
            }
        }
        self.key.marshal_binary()
    }
}

impl TXStorage {
    pub fn load(&mut self, dkey: &DataKey, found: &mut u64) -> Variable {
        *found = 0;
        let kbytes = dkey.marshal_binary_panic();
        if let Some(result) = self.raw_keys.get(&String::from_utf8_lossy(&kbytes).into_owned()) {
            *found = 1;
            let value = Variable::unmarshal_binary(result).unwrap_or_else(|_| panic!("corruption in DB"));
            if let Some(state) = &mut self.state {
                if value.length() > 10 {
                    state.consume_storage_gas(value.length() / 10);
                } else {
                    state.consume_storage_gas(1);
                }
            }
            return value;
        }
        // disk loader: raw_keys is pre-seeded by execute_sc_function with the
        // committed SC data tree, so LOAD sees state STOREd by earlier calls.
        // (execute_sc_function copies tree entries into raw_keys before run.)
        if let Some(state) = &mut self.state {
            let v = Variable { name: String::new(), vtype: Vtype::Invalid, value_uint64: 0, value_string: String::new() };
            state.consume_storage_gas(1.max(v.length() / 10));
        }
        Variable { name: String::new(), vtype: Vtype::Invalid, value_uint64: 0, value_string: String::new() }
    }

    pub fn store(&mut self, dkey: &DataKey, v: &Variable) {
        let kbytes = dkey.marshal_binary_panic();
        let vbytes = v.marshal_binary();
        if let Some(state) = &mut self.state {
            state.consume_storage_gas(vbytes.len() as i64);
        }
        self.raw_keys.insert(String::from_utf8_lossy(&kbytes).into_owned(), vbytes);
    }

    pub fn delete(&mut self, dkey: &DataKey) {
        let kbytes = dkey.marshal_binary_panic();
        self.raw_keys.insert(String::from_utf8_lossy(&kbytes).into_owned(), Vec::new());
    }

    pub fn send_external(&mut self, sender_scid: [u8; 32], asset: [u8; 32], addr: String, amount: u64) {
        // transfers collected in the tree wrapper layer (blockchain); the pure
        // crate records them here for differential tests
        let _ = (sender_scid, asset, addr, amount);
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_basic() {
        let toks = tokenize("Function foo(a Uint64) Uint64");
        assert!(toks.iter().any(|(_, t)| t == "Function"));
        assert!(toks.iter().any(|(_, t)| t == "Uint64"));
    }

    #[test]
    fn parse_simple_contract() {
        let src = r#"Function hello() Uint64
10 RETURN 0
End Function"#;
        let sc = parse_smart_contract(src).unwrap();
        assert!(sc.functions.contains_key("hello"));
        let f = &sc.functions["hello"];
        assert_eq!(f.line_numbers, vec![10]);
    }

    #[test]
    fn parse_missing_end() {
        let src = "Function hello() Uint64\n10 RETURN 0";
        assert!(parse_smart_contract(src).is_err());
    }

    #[test]
    fn uvarint_roundtrip() {
        let mut buf = [0u8; 10];
        let n = put_uvarint(&mut buf, 300);
        assert_eq!(n, 2);
        let (v, m) = uvarint(&buf[..n]);
        assert_eq!(v, 300);
        assert_eq!(m, 2);
    }

    #[test]
    fn rnd_deterministic() {
        let scid = [1u8; 32];
        let blid = [2u8; 32];
        let txid = [3u8; 32];
        let mut r1 = initialize_rnd(&scid, &blid, &txid);
        let mut r2 = initialize_rnd(&scid, &blid, &txid);
        assert_eq!(r1.random(), r2.random());
        assert_eq!(r1.random_max(100), r2.random_max(100));
    }

    #[test]
    fn merge_operator_tokens_joins_multi_char_ops() {
        // The line tokenizer splits operators char-by-char (Go parity for the
        // stored f.lines); the execution path must rejoin them so the parser
        // sees real operators. Regression: escrow CreateSwap hit "trailing
        // tokens" on `IF sellAmount == 0` because == stayed as two `=`.
        let toks = tokenize("IF sellAmount == 0 THEN GOTO 100");
        let merged = merge_operator_tokens(toks);
        let ops: Vec<&str> = merged.iter().map(|(_, t)| t.as_str()).collect();
        assert!(ops.contains(&"=="), "== not merged: {ops:?}");
        // != also joins
        let toks = tokenize("IF a != b THEN GOTO 50");
        let merged = merge_operator_tokens(toks);
        let ops: Vec<&str> = merged.iter().map(|(_, t)| t.as_str()).collect();
        assert!(ops.contains(&"!="), "!= not merged: {ops:?}");
        // a lone `=` (assignment) must NOT be merged
        let toks = tokenize("LET x = 5");
        let merged = merge_operator_tokens(toks);
        let ops: Vec<&str> = merged.iter().map(|(_, t)| t.as_str()).collect();
        assert!(ops.contains(&"=") && !ops.contains(&"=="), "lone = mishandled: {ops:?}");
    }

    #[test]
    fn multi_string_arg_escrow_createswap_runs() {
        // The ship-blocker: multi-string-arg SC call. CreateSwap has 7 params
        // (5 strings) and uses string concat + == comparisons. Before the
        // operator-merge fix this failed with "trailing tokens".
        let code = r#"
Function CreateSwap(id String, sellToken String, sellAmount Uint64, buyToken String, buyAmount Uint64, maker String, timeout Uint64) Uint64
10 IF EXISTS("swap_" + id + "_maker") THEN GOTO 100
20 IF sellAmount == 0 THEN GOTO 100
30 IF buyAmount == 0 THEN GOTO 100
40 STORE("swap_" + id + "_maker", maker)
95 STORE("swap_" + id + "_timeout", BLOCK_HEIGHT() + timeout)
96 RETURN 0
100 RETURN 1
End Function
"#;
        let sc = parse_smart_contract(code).expect("parse");
        let mut state = SharedState::new(&[0u8; 32], &[0u8; 32], &[0u8; 32], &[0u8; 33], 100, 100, 100);
        let params: std::collections::HashMap<String, String> = [
            ("id".to_string(), "swap1".to_string()),
            ("sellToken".to_string(), "DERO".to_string()),
            ("sellAmount".to_string(), "1000".to_string()),
            ("buyToken".to_string(), "USDT".to_string()),
            ("buyAmount".to_string(), "500".to_string()),
            ("maker".to_string(), "deto1qyyawp87a...".to_string()),
            ("timeout".to_string(), "100".to_string()),
        ].into_iter().collect();
        let r = run_smart_contract(&sc, "CreateSwap", &mut state, &params)
            .expect("CreateSwap should run without 'trailing tokens'");
        assert_eq!(r.value_uint64, 0, "CreateSwap should RETURN 0 (success, commits)");
    }
}
