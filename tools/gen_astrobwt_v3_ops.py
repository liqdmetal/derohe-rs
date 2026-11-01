#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
#
"""Generate the AstroBWTv3 op-switch (Rust) from the Go reference pow.go.

Each `case N:` block in pow.go is a 4-5 line sequence of byte operations on
step_3[pos1..pos2] (plus per-case tails for cases 0, 253, 254/255). This
script parses those bodies and emits an equivalent Rust `match` arm.
Mechanical, so a typo can't hide: the mapping table is exhaustive.
"""
import re

SRC = os.environ.get("SRC", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "derohe-reference", "astrobwt", "astrobwtv3", "pow.go")))
OUT = os.environ.get("OUT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "crypto", "src", "astrobwt_v3_ops.rs")))

src = open(SRC, encoding="utf-8").read()

# extract per-case bodies: case N: ... INSERT_RANDOM_CODE_START ... (byte ops)
# ... INSERT_RANDOM_CODE_END ... (optional per-case tail lines, e.g. case 253)
case_re = re.compile(
    r"case (\d+)(?:, (\d+))?:.*?INSERT_RANDOM_CODE_START\n(.*?)(?=\n\t\tcase |\n\t\tdefault)",
    re.S,
)

def split_body(raw: str):
    """byte ops between the START/END markers; tail lines after END."""
    parts = re.split(r"\n\s*//INSERT_RANDOM_CODE_END", raw, maxsplit=1)
    ops = [l for l in parts[0].splitlines() if l.strip()]
    tail = []
    if len(parts) > 1:
        tail = [l for l in parts[1].splitlines() if l.strip() and l.strip() != "}"]
    return ops, tail

def map_op(line: str) -> str:
    line = line.strip()
    # strip trailing // comments
    line = re.sub(r"\s*//.*$", "", line).strip()
    # per-case tails that are NOT byte ops
    if line.startswith("prev_lhash = lhash + prev_lhash"):
        return line.replace("step_3", "s").replace(
            "prev_lhash = lhash + prev_lhash", "prev_lhash = lhash.wrapping_add(prev_lhash)")
    if line.startswith("lhash = xxhash.Sum64"):
        return "lhash = xxh64(&s[..pos2 as usize], 0);"
    if line.startswith("lhash = fnv1a.HashBytes64"):
        return "lhash = fnv1a64(&s[..pos2 as usize]);"
    if line.startswith("lhash = siphash.Hash"):
        return "lhash = siphash24(tries, prev_lhash, &s[..pos2 as usize]);"
    if line.startswith("rc4s = NewCipher"):
        return "rc4s = Rc4::new(&s);"

    ops = [
        (r"step_3\[i\] = step_3\[i\] \^ bits\.RotateLeft8\(step_3\[i\], (\d)\)",
         lambda m: f"s[i] ^= s[i].rotate_left({m.group(1)})"),
        (r"step_3\[i\] = step_3\[i\] \^ byte\(bits\.OnesCount8\(step_3\[i\]\)\)",
         "s[i] ^= s[i].count_ones() as u8"),
        (r"step_3\[i\] = bits\.RotateLeft8\(step_3\[i\], 5\)",
         "s[i] = s[i].rotate_left(5)"),
        (r"step_3\[i\] = bits\.RotateLeft8\(step_3\[i\], int\(step_3\[i\]\)\)",
         "s[i] = s[i].rotate_left(s[i] as u32)"),
        (r"step_3\[i\] = bits\.RotateLeft8\(step_3\[i\], (\d)\)",
         lambda m: f"s[i] = s[i].rotate_left({m.group(1)})"),
        (r"step_3\[i\] \*= step_3\[i\]", "s[i] = s[i].wrapping_mul(s[i])"),
        (r"step_3\[i\] = bits\.Reverse8\(step_3\[i\]\)", "s[i] = s[i].reverse_bits()"),
        (r"step_3\[i\] = \^step_3\[i\]", "s[i] = !s[i]"),
        (r"step_3\[i\] = step_3\[i\] >> \(step_3\[i\] & 3\)", "s[i] >>= s[i] & 3"),
        (r"step_3\[i\] = step_3\[i\] << \(step_3\[i\] & 3\)", "s[i] <<= s[i] & 3"),
        (r"step_3\[i\] \+= step_3\[i\]", "s[i] = s[i].wrapping_add(s[i])"),
        (r"step_3\[i\] -= \(step_3\[i\] \^ 97\)", "s[i] = s[i].wrapping_sub(s[i] ^ 97)"),
        (r"step_3\[i\] = step_3\[i\] \^ step_3\[pos2\]", "s[i] ^= s[pos2]"),
        (r"step_3\[i\] = step_3\[i\] & step_3\[pos2\]", "s[i] &= s[pos2]"),
        (r"step_3\[pos2\], step_3\[pos1\] = bits\.Reverse8\(step_3\[pos1\]\), bits\.Reverse8\(step_3\[pos2\]\)",
         "let t = s[pos1].reverse_bits();\n                    s[pos1] = s[pos2].reverse_bits();\n                    s[pos2] = t;"),
    ]
    for pat, repl in ops:
        if re.fullmatch(pat, line):
            return repl if isinstance(repl, str) else repl(re.match(pat, line))
    raise ValueError(f"unmapped op line: {line!r}")

cases = {}
for m in case_re.finditer(src):
    nums = [int(m.group(1))]
    if m.group(2):
        nums.append(int(m.group(2)))  # "case 254, 255:"
    ops, tail = split_body(m.group(3))
    mapped_ops = [map_op(l) for l in ops]
    mapped_tail = [map_op(l) for l in tail]
    for num in nums:
        cases[num] = {"ops": mapped_ops, "tail": mapped_tail}

# sanity: expect 0..=255 all present
missing = [n for n in range(256) if n not in cases]
if missing:
    raise SystemExit(f"missing cases: {missing[:10]}")

out = []
out.append("// Generated from the Go reference astrobwt/astrobwtv3/pow.go — do not edit.\n")
out.append("// The op-switch body: applied to s[pos1..pos2] (Go: step_3).\n")
out.append("// Tail lines (lhash/rc4 updates) run in place after the byte ops.\n")
out.append("#[inline]\n")
out.append("pub fn apply_op(op: u8, s: &mut [u8; 256], pos1: usize, pos2: usize,")
out.append("                rc4s: &mut Rc4, tries: u64, lhash_out: &mut u64, prev_out: &mut u64) {")
out.append("    // rebind to locals so the generated bodies can use them directly")
out.append("    let (mut lhash, mut prev_lhash) = (*lhash_out, *prev_out);")
out.append("    match op {")

for n in range(256):
    body = cases[n]
    ops = body["ops"]
    tail = body["tail"]
    rekey = [l for l in ops if l.startswith("rc4s = Rc4::new")]
    byteops = [l for l in ops if l not in rekey]
    if n in (254, 255):
        # Go's case 254/255 rekeys rc4s BEFORE the byte-op loop, and the
        # rekey line sits above the INSERT_RANDOM_CODE marker (not captured)
        rekey = ["*rc4s = Rc4::new(s);"] + rekey
    arm = [f"        {n} => {{"]
    for l in rekey:
        arm.append(f"            {l};")
    if byteops:
        arm.append("            for i in pos1..pos2 {")
        for l in byteops:
            arm.append(f"                {l};")
        # Go puts the lhash tails INSIDE the loop body (case 253: the update
        # runs once per byte position)
        for l in tail:
            arm.append(f"                {l}" + ("" if l.endswith(";") else ";"))
        arm.append("            }")
    else:
        for l in tail:
            arm.append(f"            {l}" + ("" if l.endswith(";") else ";"))
    arm.append("        }")
    out.append("\n".join(arm))

out.append("        _ => {}")
out.append("    }")
out.append("    *lhash_out = lhash;")
out.append("    *prev_out = prev_lhash;")
out.append("}")

open(OUT, "w", encoding="utf-8").write("\n".join(out) + "\n")
print(f"generated {OUT}: {len(cases)} cases")
