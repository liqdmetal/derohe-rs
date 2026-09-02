# derohe-rs — clean-room Rust DERO node, wallet, and consensus core

A from-scratch Rust implementation of the DERO protocol — consensus
cryptography, state transitions, a runnable node, and a working wallet —
verified **byte-for-byte against the Go reference** via differential testing.

**BSD 3-Clause.** Clean-room: written from the DERO protocol spec; the Go
reference (`deroproject/derohe`, DERO Research License v1.1.2) is used only
as a black-box test oracle and never committed. See `NOTICE.md`.

## What works (all live-verified)

| Layer | Status |
|---|---|
| Consensus core | 2,578+ differential vectors + 71 unit + 4 integration tests, byte-identical vs Go |
| Block/chain | byte-identical replay; mainnet BLIDs reproduce 29/29; reorg 27/27 |
| PoW | AstroBWTv3 byte-identical (90/90 live miniblocks) |
| Smart contracts | DVM parse/run byte-identical; SC install 16/16; SC deploy via wallet |
| Node | syncs the reference chain, verified mempool, mines, P2P relay + keep-sync, wallet RPCs (`DERO.Transfer`, `--seed`) |
| Wallet | recovery words → keys → tx build → proof → broadcast; **tx mined + executed on the Go chain** (wdst balance moved) |
| End-to-end | **Rust wallet → Rust node → Rust-mined block → second Rust node synced**, all in Rust |

## Layout

```
oracle/            Go oracle: JSONL shim over the real derohe crypto (test only)
crypto/            Rust crate (dero-crypto): clean-room implementation
  src/keccak.rs        keccak256/512 (incl. derohe's 512-truncates-to-32 quirk)
  src/curve.rs         alt_bn128 point codec (DERO 33-byte compression) + group ops
  src/hash_to_point.rs hash-to-curve + protocol base G
  src/elgamal.rs       account-model ElGamal (commit/add/plus/serdes)
  src/fieldvector.rs   FieldVector (raw-bytes storage, mod-n arithmetic)
  src/pedersen.rs      Pedersen params/commitments + multiexp
  src/pointvector.rs   PointVector (slice/add/hadamard/multiexp)
  src/fft.rs           NTT FFT + convolution
  src/polynomial.rs    Polynomial quirks + RecursivePolynomials
  src/innerproduct.rs  inner-product argument
  src/bulletproof.rs   aggregate bulletproof (generate/verify/serialize)
  src/balance_serdes.rs NonceBalance wire format
  src/statement.rs     Statement wire format (blake2s pointers, C/D/roothash)
  src/rpc_args.rs      SCDATA canonical CBOR args
  src/transaction.rs   Transaction serialization/hashing (all 6 types)
  src/block.rs         Block + MiniBlock serialization/hashing
  src/astrobwt.rs      AstroBWT PoW (legacy)
  src/astrobwt_v3.rs   AstroBWTv3 (current mainnet PoW)
  src/dvm.rs           DVM: tokenizer, parser, interpreter, 36 builtins
  src/rpc_addr.rs      bech32 DERO address <-> compressed key
  src/graviton.rs      state tree (blake2s key-hash bit-trie)
  src/chain.rs         state transitions: rewards, miner-tx, balances, SC
  src/wallet.rs        key derivation, shared secrets, BSGS balance decode
  src/tx_builder.rs    wallet BuildTransaction (NORMAL + SC install)
  src/bin/node.rs      dero-node: sync, mempool, mining, RPC, P2P, --seed wallet
  src/bin/wallet.rs    standalone wallet CLI (transfer / --sc-install)
harness/           differential + replay test suites
wallet-ffi/        C-FFI wallet SDK (Swift/JNI)
wasm-light-client/ WASM light client (address, keys, deserialize, verify)
derohe-reference/  Go reference (gitignored; differential oracle only)
```

## How to run

```bash
# differential suite (builds both oracles, runs all vectors)
python3 harness/difftest.py
cd crypto && cargo test --release        # 71 unit tests

# node: sync + mine + wallet in one
./crypto/target/release/node.exe \
  --peer http://127.0.0.1:25000/json_rpc --port 26000 --mine \
  --miner <hex-key-or-bech32> --seed "<recovery words>"
# then: DERO.Transfer {dest, amount} or {dest, sc_code} deploys/transfers

# standalone wallet
./crypto/target/release/wallet.exe "<words>" <dest> <amount> <daemon>
./crypto/target/release/wallet.exe "<words>" --sc-install "<code>" <daemon>
```

Toolchain notes (Windows): Rust `x86_64-pc-windows-gnu` host; TDM-GCC lacks
`libgcc_eh.a` — `crypto/.cargo/config.toml` points the linker at an empty
archive in `~/rust-libs/libgcc_eh.a` (all deps are pure Rust).

## Reference quirks replicated (the research record)

1. **`Keccak512` truncates to 32 bytes** (`cryptography/crypto/keccak.go:33`).
2. **Protocol G is not (1,2):** `G = HashToPoint(keccak256("DEROG"))` =
   `02eacfbf92b94015c9b0b3d901dae37ec68f74dea7e4484c76d505aade4ad7c001`.
3. **DERO compressed points are not SEC1:** 33 bytes = x (BE) + flag
   (`0x00` smaller y, `0x01` larger).
4. **HashToPoint reduces the seed mod n, increments mod p.**
5. **Identity is not representable** in the codec (x=0 → non-residue → decode
   fails; Go panics on the zero ciphertext, Rust errors).
6. **Scalar mult is full-integer double-and-add** (no pre-reduction).
7. **FieldVector stores RAW (unreduced) big.Ints** — identity ops round-trip
   values ≥ n unreduced.
8. **`Polynomial.Mul` only handles ×(x+1) binomials.**
9. **Pedersen bases:** `Gs[i] = HashToPoint(keccak256("DEROG"‖BE32(i)))`,
   i < 128; `H` from "DEROH"; `GSUM = Σ Gs[i]`.
10. **IP transcripts use UNCOMPRESSED points** (64-byte Marshal, not DERO
    compression).
11. **Bulletproof randomness draw order** (GenerateProof): BA, sL/sR, BS,
    aa (skipping i=0,m), A, B, phi/chi/psi INTERLEAVED, C_XG, T1, T2,
    k_sk/k_r/k_b/k_tau — 264+6m draws.
12. **z_A = B_rand·w + A_rand** (B-commit randomness, not BS).
13. **Verify needs the full statement** (CLn/CRn/C); the full accept path is
    exercised at chain replay against real mainnet txs.
14. **Statement wire omits CLn/CRn** (Go comments them out; the chain
    re-expands them from the balance tree).
15. **Wallet tx bpp = 2** (not mainnet 3); txid = keccak(core statement)
    with the statement's own bpp.
16. **SC txs are TX_SC = 5** (not 1); fees include
    `len(scdata_marshal) × 15/10`.

## Intentional divergence

- **`x >= p` compressed decode:** Go "succeeds" with an invalid point
  (`bn256/changes.go:59` discards the on-curve error); Rust rejects.
  Consensus impact: none for valid txs (points originate from valid proofs).

## License

BSD 3-Clause (see `LICENSE`, `NOTICE.md`). `oracle/` and
`derohe-reference/` are DERO Research License v1.1.2 test glue — never
committed, never copied into the Rust crate.
