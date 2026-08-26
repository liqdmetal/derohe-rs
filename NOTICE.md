# NOTICE

## Licensing

**This repository is licensed under the BSD 3-Clause License** (see
`LICENSE`). It is a clean-room, from-scratch Rust reimplementation of the
consensus-critical portions of the DERO protocol.

### The Go reference (deroproject/derohe) is NOT part of this repository

The DERO Go implementation (`deroproject/derohe`) is licensed separately by
the DERO Project under the **DERO Research License v1.1.2**, which permits
research use only and requires a commercial license for commercial use.
That license does NOT apply to this repository:

- This repository contains **no source code from derohe**. The reference
  tree is fetched into `derohe-reference/` (gitignored) solely to run as a
  **differential-testing oracle** and is never committed.
- All Rust, Python, and supporting code here was **independently authored**
  from the DERO protocol specification and public documentation.
- The reference implementation was used exclusively as a black-box test
  oracle: inputs are fed to both implementations and outputs compared
  byte-for-byte. No code was copied, translated, or derived from it.

### Protocol facts are not copyrightable expression

Standard, publicly documented protocol elements — the `"DERO"` constant,
the `G = HashToPoint(keccak256("DEROG"))` base point, the alt_bn128 (BN254)
curve parameters, message formats, and consensus rules — are facts of a
published protocol, not copyrightable expression. This implementation
expresses those facts in original Rust code.

## Provenance

- **Method**: differential testing against the Go reference (see
  `harness/difftest.py`). Every consensus-critical operation is verified
  byte-for-byte against the reference.
- **Precedent**: XELIS — a BSD-3-Clause, from-scratch Rust implementation of
  a DERO-style ElGamal blockDAG — demonstrates this licensing path is
  accepted in the ecosystem.
- **Verification record**: 2,575+ differential vectors, 66 unit tests,
  mainnet block replay (BLIDs byte-identical), smart-contract install/call
  replay, and end-to-end wallet transactions mined on a local reference
  network.

## Copyright

Copyright (c) 2026, liqdmetal and contributors.
