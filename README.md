# derohe-rs — clean-room Rust reimplementation of DERO's consensus crypto

Phase 0/1 spike: **differential testing harness + first crypto module**, proving
that a Rust implementation can be verified byte-for-byte against the Go
reference (`deroproject/derohe`) before we commit to the full port.

**Status: PASS — 1,533 differential vectors (default run) + 24 unit tests,
byte-identical with the Go reference** (1 documented divergence, see below).
Stress runs with 500 vectors/op exceed 4,500 vectors, all green.

## Why this exists

derohe is under the **DERO Research License v1.1.2** (non-commercial). The goal
is a fresh Rust implementation of the same algorithms under a permissive
license — the same escape hatch XELIS (BSD-3) proved viable — that is
**provably consensus-compatible** with DERO mainnet. The proof mechanism is
differential testing: the Go node is the oracle; the Rust code must agree with
it byte-for-byte on everything that affects consensus.

## Layout

```
oracle/            Go oracle: calls the REAL derohe cryptography packages
                   (JSONL request/response over stdin/stdout)
crypto/            Rust crate (dero-crypto): clean-room implementation
  src/keccak.rs        legacy keccak256/512
  src/curve.rs         alt_bn128 point codec (DERO compression) + group ops
  src/hash_to_point.rs try-and-increment hash-to-curve + protocol G
  src/elgamal.rs       account-model ElGamal (commit/add/plus/mul/neg/serdes)
  src/fieldvector.rs   FieldVector (raw-bytes storage, mod-n arithmetic)
  src/pedersen.rs      Pedersen params/commitments + point-vector multiexp
  src/pointvector.rs   PointVector (slice/extract/add/hadamard/multiexp)
  src/fft.rs           NTT FFT + convolution (fft_FieldVector et al)
  src/polynomial.rs    Polynomial.Mul quirk + RecursivePolynomials
  src/innerproduct.rs  inner-product argument (generate/verify/serialize)
  src/bin/oracle.rs    Rust oracle: same JSONL protocol as oracle/
harness/difftest.py Python differential tester (deterministic vectors)
derohe-reference/  Reference Go source (gitignored; fetched via tarball —
                   a plain `git clone` fails on Windows: vendor/ contains
                   `API????.md`, an invalid Windows filename)
```

## How to run

```bash
# one-time: fetch reference source (see derohe-reference/README note)
python3 harness/difftest.py            # builds both oracles, runs full suite
python3 harness/difftest.py --no-build # skip rebuild
python3 harness/difftest.py --vectors 500   # more random vectors per op
cd crypto && cargo test --release      # Rust unit tests
```

Toolchain notes (Windows):
- Rust: `rustup` with `x86_64-pc-windows-gnu` host (no MSVC needed).
- TDM-GCC-64 lacks `libgcc_eh.a`; `crypto/.cargo/config.toml` points the
  linker at an empty archive in `~/rust-libs/libgcc_eh.a` (all deps are pure
  Rust — no C++ objects need real gcc_eh).

## What's verified (differential, vs Go reference)

| Area | Ops | Notes |
|---|---|---|
| Keccak | keccak256, keccak512 | incl. derohe's truncation quirk |
| Hash-to-point | hashtopoint, base_g | protocol G pinned: `02eacfbf…c001` |
| Group ops | scalarmult, add, neg, uncompressed marshal | edge scalars 0, 1, n±1, p±1, 2^255 |
| ElGamal | commit, add, plus, mul, neg, serialize, deserialize | deterministic injected randomness |
| FieldVector | add, hadamard, innerproduct, times, negate, flip, extract, concat, sum | raw-bytes identity ops + mod-n arithmetic |
| Pedersen | gparams (G,H,GSUM,all 128 Gs/Hs), commit, commit_scalar | mainnet params pinned by oracle |
| PointVector | multiexp | against hash-to-point pool |
| FFT | fft_fieldvector, fft_generatorvector, convolution | forward + inverse, unity root pinned |
| Polynomial | mul (binomial quirk), recursive_polynomials | b-coefficients are bits |
| Inner product | ip_generate (n=2,8,128), ip_verify, cross-verify | byte-identical proofs; Go⇄Rust cross-verification accepts |
| Errors | malformed deserialize (short/long/non-QR) | both sides reject identically |

## Reference quirks discovered (and replicated)

1. **`Keccak512` truncates to 32 bytes.** Go's `Hash` is `[32]byte`;
   `Keccak512` copies only the first half of the 64-byte digest
   (`cryptography/crypto/keccak.go:33-41`). Replicated exactly.
2. **Protocol base G is not (1,2).** `G = HashToPoint(keccak256("DEROG"))`
   (`generatorparams.go:31`, `const.go:27`). Pinned by oracle:
   `02eacfbf92b94015c9b0b3d901dae37ec68f74dea7e4484c76d505aade4ad7c001`.
3. **DERO compressed point format is not SEC1.** 33 bytes = x (BE) + flag byte;
   flag `0x00` = smaller y-root, `0x01` = larger (`bn256/changes.go:19-35`).
4. **HashToPoint reduces seed mod n, increments mod p** (`hashtopoint.go:105-143`).
5. **Identity is not representable in the compressed codec.** Identity encodes
   to 33 zero bytes, and x=0 makes x³+3 = 3 a non-residue mod p → decode
   fails. Go's `Deserialize` panics on the zero ciphertext; Rust mirrors this.
6. **Scalar mult is full-integer double-and-add** (no pre-reduction mod n —
   group order handles it), matching Go's `big.Int` ladder.
7. **FieldVector stores RAW (unreduced) big.Ints.** Identity ops
   (flip/extract/slice/concat) return raw bytes; only arithmetic ops reduce
   mod n (`algebra_fieldvector.go`). Values ≥ n round-trip unreduced through
   flip/extract. Rust mirrors this with raw 32-byte storage.
8. **`Polynomial.Mul` only handles ×(x+1) binomials** (`polynomial.go:44-63`) —
   a quirk to replicate when the proof package is ported.
9. **Pedersen vector bases**: `Gs[i] = HashToPoint(keccak256("DEROG" ||
   BE32(i)))` for i in 0..128 (Go zero-pads the hex of i to 64 chars == BE32);
   `H` from "DEROH"; `GSUM = Σ Gs[i]`. All pinned by the oracle.
10. **IP challenge transcripts use UNCOMPRESSED points.** The inner-product
    folding hashes `prev_challenge || L.Marshal() || R.Marshal()` (64-byte
    uncompressed), not the DERO-compressed form (`proof_innerproduct.go:144`).
11. **`Polynomial.Mul` requires the linear coefficient == 1** (only multiplies
    by binomials (x + c)); anything else silently produces the unshifted
    product (`polynomial.go:51`). The recursion feeds it only 0/1-bit b values.
12. **FFT unity root**: primitive 2^28-th root of unity mod n,
    `14a3074b...46edd`; omega = unity^((2^28)/length)
    (`fieldvector.go:166-169`).

## Documented divergences (intentional)

- **`x >= p` in compressed decode is UB in Go** (`bn256/changes.go:59` discards
  the on-curve `Unmarshal` error; any flag ≠ 0x01 falls through to "return
  y1"). Go "succeeds" with an invalid point; Rust rejects. Consensus impact:
  none for valid txs (points originate from valid proofs); to be re-checked at
  chain-replay phase against real mainnet txs.

## What's next (Phase 4+)

- `proof_generate.go` / `proof_verify.go` (the aggregate bulletproof:
  range/balance proofs over the inner-product argument, with injected
  randomness for deterministic differential testing)
- `balance_serdes.go` (account balance serialization — the on-chain state)
- tx/block serialization and hashing → then genesis-to-tip mainnet replay:
  the definitive consensus test
- DVM interpreter (the hardest piece; see project spec)

## License

- **Rust crate (`crypto/`): DERO Research License v1.1.2** (see LICENSE) —
  **research-only**, matching the DERO ecosystem license. This is a
  deliberate decision to keep the port within DERO's licensing family:
  non-commercial research/evaluation/development use, no commercial gain.
  Clean-room: written from the DERO reference source + protocol spec,
  NOT copied from it.
- **`oracle/` (Go): test-only glue.** It links the REAL derohe packages
  (under the same DERO Research License v1.1.2) via the `replace`
  directive to `../derohe-reference`. The oracle source is a thin JSONL
  shim; the reference it links is gitignored and never committed. It is
  a test harness, not part of the crate, and carries the same
  non-commercial constraint as the DERO code it calls.
- **`derohe-reference/`**: DERO Research License v1.1.2 — **test oracle
  only, never committed, never copied into the Rust crate** (clean-room).
