// SPDX-License-Identifier: BSD-3-Clause
// Atomic settlement (hash-lock / HTLC) — RelayOS ADR-0041/0043 "atomicity
// without custody". Two-leg swap with REAL value movement:
//   CreateSwap -> Fund (locks value into SC) -> Claim (reveal preimage, pays
//   out to taker) | Refund (after timeout, funder only, pays out to funder).
// Grounded in DERO DVM constraints:
//     - success = RETURN 0 (nonzero is "Discarded knowingly" -> no commit)
//     - recipient addresses stored as compressed 33-byte keys (SIGNER() is
//       zero on ringsize-4 txs, unusable for payout)
//     - hash-lock: SHA256(preimage) == stored hashlock enables cross-leg
//       atomicity (Tier Nolan reveal)
//     - payout legs run only when the entrypoint returns 0; on failure the
//       value stays locked in the SC balance
//
// The transfer plumbing (DVM send_external -> TreeWrapper.transfers) is what
// makes SEND_* actually move value; this test asserts those transfers appear
// exactly once each payout, with the correct asset/address/amount.

use dero_crypto::curve::{decode_compressed, encode_compressed};
use dero_crypto::dvm::{parse_smart_contract, SmartContract};
use dero_crypto::rpc_args::{Argument, ArgValue, Arguments, DATA_HASH, DATA_STRING, DATA_UINT64};
use dero_crypto::sc::{execute_sc_function, seed_store_from_tree, TreeWrapper, TransferExternal};

fn new_tree_wrapper() -> TreeWrapper {
    TreeWrapper::new(dero_crypto::graviton::Tree::new("atomic-swap-test"))
}

// Valid compressed curve points used as payout addresses. The alt_bn128
// generator G=(1,2) encodes (DERO codec) to [0..0, 1, 0x00]; -G to
// [0..0, 1, 0x01]. Both decode cleanly (pinned by curve::generator_roundtrip)
// so the SEND_* leg's decode_compressed check passes, AND both are valid UTF-8
// (only control chars), so they survive DVM string STORE/LOAD byte-for-byte
// without lossy re-encoding.
fn gen_addr() -> String {
    let mut s = [0u8; 33];
    s[31] = 1; // x = 1
    s[32] = 0x00; // G: y = 2 (smaller) -> flag 0x00
    debug_assert!(decode_compressed(&s).is_ok());
    String::from_utf8_lossy(&s).into_owned()
}
fn neg_g_addr() -> String {
    let mut s = [0u8; 33];
    s[31] = 1; // x = 1
    s[32] = 0x01; // -G: y = p-2 (larger) -> flag 0x01
    debug_assert!(decode_compressed(&s).is_ok());
    String::from_utf8_lossy(&s).into_owned()
}
// Any x whose point is on alt_bn128 (y^2 = x^3 + 3) and whose compressed
// encoding stays valid UTF-8 (all bytes < 0x80). Used to get a THIRD distinct
// valid payout address distinct from G and -G (e.g. a griefing attacker).
fn x_addr(x: u8) -> String {
    let mut s = [0u8; 33];
    s[31] = x; // x coordinate
    s[32] = 0x00;
    debug_assert!(decode_compressed(&s).is_ok(), "x={x} not on curve");
    String::from_utf8_lossy(&s).into_owned()
}

fn atomic_swap_code() -> &'static str {
    r#"
Function Initialize() Uint64
10 RETURN 0
End Function

Function CreateSwap(id String, maker String, taker String, sellToken String, sellAmount Uint64, buyToken String, buyAmount Uint64, hashlock String, timeout Uint64) Uint64
10 IF EXISTS("swap_" + id + "_maker") THEN GOTO 100
20 IF sellAmount == 0 THEN GOTO 100
30 IF buyAmount == 0 THEN GOTO 100
40 IF timeout == 0 THEN GOTO 100
50 STORE("swap_" + id + "_maker", maker)
55 STORE("swap_" + id + "_taker", taker)
60 STORE("swap_" + id + "_sellToken", sellToken)
70 STORE("swap_" + id + "_sellAmount", sellAmount)
80 STORE("swap_" + id + "_buyToken", buyToken)
90 STORE("swap_" + id + "_buyAmount", buyAmount)
95 STORE("swap_" + id + "_hashlock", hashlock)
96 STORE("swap_" + id + "_state", 0)
97 STORE("swap_" + id + "_timeout", BLOCK_HEIGHT() + timeout)
98 RETURN 0
100 RETURN 1
End Function

Function Fund(id String, funder String) Uint64
10 IF EXISTS("swap_" + id + "_maker") == 0 THEN GOTO 100
20 IF LOAD("swap_" + id + "_state") != 0 THEN GOTO 100
30 IF LOAD("swap_" + id + "_maker") != funder THEN GOTO 100
40 IF DEROVALUE() < LOAD("swap_" + id + "_sellAmount") THEN GOTO 100
50 STORE("swap_" + id + "_funded", DEROVALUE())
60 STORE("swap_" + id + "_state", 1)
70 RETURN 0
100 RETURN 1
End Function

Function Claim(id String, preimage String) Uint64
10 IF LOAD("swap_" + id + "_state") != 1 THEN GOTO 100
20 IF HEX(SHA256(preimage)) != LOAD("swap_" + id + "_hashlock") THEN GOTO 100
30 SEND_DERO_TO_ADDRESS(LOAD("swap_" + id + "_taker"), LOAD("swap_" + id + "_funded"))
40 STORE("swap_" + id + "_state", 2)
50 RETURN 0
100 RETURN 1
End Function

Function Refund(id String, funder String) Uint64
10 IF LOAD("swap_" + id + "_state") != 1 THEN GOTO 100
20 IF BLOCK_HEIGHT() <= LOAD("swap_" + id + "_timeout") THEN GOTO 100
30 IF LOAD("swap_" + id + "_maker") != funder THEN GOTO 100
40 SEND_DERO_TO_ADDRESS(LOAD("swap_" + id + "_maker"), LOAD("swap_" + id + "_funded"))
50 STORE("swap_" + id + "_state", 3)
60 RETURN 0
100 RETURN 1
End Function

Function GetState(id String) Uint64
10 IF EXISTS("swap_" + id + "_maker") == 0 THEN GOTO 100
20 RETURN LOAD("swap_" + id + "_state")
100 RETURN 99
End Function

Function GetMaker(id String) String
10 IF EXISTS("swap_" + id + "_maker") == 0 THEN GOTO 100
20 RETURN LOAD("swap_" + id + "_maker")
100 RETURN ""
End Function

Function GetTaker(id String) String
10 IF EXISTS("swap_" + id + "_maker") == 0 THEN GOTO 100
20 RETURN LOAD("swap_" + id + "_taker")
100 RETURN ""
End Function

Function GetFunded(id String) Uint64
10 IF EXISTS("swap_" + id + "_maker") == 0 THEN GOTO 100
20 RETURN LOAD("swap_" + id + "_funded")
100 RETURN 0
End Function
"#
}

struct Ctx {
    data_tree: TreeWrapper,
    sc_meta: TreeWrapper,
    scid: [u8; 32],
    sc: SmartContract,
    bl_height: u64,
    blid: [u8; 32],
    txid: [u8; 32],
}

impl Ctx {
    fn new(bl_height: u64) -> Self {
        let sc = parse_smart_contract(atomic_swap_code()).expect("parse atomic_swap.s");
        let scid = [0x0f; 32];
        Ctx {
            data_tree: new_tree_wrapper(),
            sc_meta: new_tree_wrapper(),
            scid,
            sc,
            bl_height,
            blid: [0xcc; 32],
            txid: [0xdd; 32],
        }
    }

    fn call(&mut self, entrypoint: &str, args: Vec<(String, ArgValue)>, incoming: u64) -> u64 {
        let mut a: Vec<Argument> = vec![
            Argument { name: "SC_ACTION".into(), data_type: DATA_UINT64, value: ArgValue::U64(0) },
            Argument { name: "SC_ID".into(), data_type: DATA_HASH, value: ArgValue::Hash(self.scid) },
            Argument { name: "entrypoint".into(), data_type: DATA_STRING, value: ArgValue::Str(entrypoint.into()) },
        ];
        for (k, v) in args {
            let (dt, val) = match v {
                ArgValue::U64(u) => (DATA_UINT64, ArgValue::U64(u)),
                ArgValue::Str(s) => (DATA_STRING, ArgValue::Str(s)),
                other => (DATA_STRING, other),
            };
            a.push(Argument { name: k, data_type: dt, value: val });
        }
        let args = Arguments(a);
        let bytes = args.marshal_binary().expect("marshal scdata");
        let mut incoming_map = std::collections::HashMap::new();
        if incoming > 0 {
            incoming_map.insert([0u8; 32], incoming);
        }
        self.txid[0] = self.txid[0].wrapping_add(1);
        match execute_sc_function(
            &mut self.sc_meta, &mut self.data_tree, &self.scid,
            self.bl_height, self.bl_height, self.bl_height, &self.blid, &self.txid,
            &self.sc, entrypoint, 0, &[0u8; 33], &incoming_map, &bytes, 0,
        ) {
            Ok((ret, _gas)) => ret,
            Err(e) if e == "Discarded knowingly" => 1,
            Err(e) => panic!("execute_sc_function: {e}"),
        }
    }

    // Transfers accumulated in the wrapper after the last call — the SEND_*
    // payout legs land here.
    fn transfers(&self) -> &[TransferExternal] {
        &self.data_tree.transfers
    }

    fn query_string(&mut self, entrypoint: &str, id: &str) -> String {
        let a: Vec<Argument> = vec![
            Argument { name: "SC_ACTION".into(), data_type: DATA_UINT64, value: ArgValue::U64(0) },
            Argument { name: "SC_ID".into(), data_type: DATA_HASH, value: ArgValue::Hash(self.scid) },
            Argument { name: "entrypoint".into(), data_type: DATA_STRING, value: ArgValue::Str(entrypoint.into()) },
            Argument { name: "id".into(), data_type: DATA_STRING, value: ArgValue::Str(id.into()) },
        ];
        let args = Arguments(a.clone());
        let bytes = args.marshal_binary().expect("marshal scdata");
        let params: std::collections::HashMap<String, String> = {
            let mut p = std::collections::HashMap::new();
            if let Some(f) = self.sc.functions.get(entrypoint) {
                for fp in &f.params {
                    if let Some(v) = args.get_string(&fp.name) { p.insert(fp.name.clone(), v); }
                }
            }
            p
        };
        let mut state = dero_crypto::dvm::SharedState::new(&self.scid, &self.blid, &self.txid, &[0u8; 33], self.bl_height, self.bl_height, self.bl_height);
        seed_store_from_tree(&mut state.store, &self.data_tree);
        let r = dero_crypto::dvm::run_smart_contract(&self.sc, entrypoint, &mut state, &params)
            .expect("read-only query");
        r.value_string
    }

    fn query_uint64(&mut self, entrypoint: &str, id: &str) -> u64 {
        let a: Vec<Argument> = vec![
            Argument { name: "SC_ACTION".into(), data_type: DATA_UINT64, value: ArgValue::U64(0) },
            Argument { name: "SC_ID".into(), data_type: DATA_HASH, value: ArgValue::Hash(self.scid) },
            Argument { name: "entrypoint".into(), data_type: DATA_STRING, value: ArgValue::Str(entrypoint.into()) },
            Argument { name: "id".into(), data_type: DATA_STRING, value: ArgValue::Str(id.into()) },
        ];
        let args = Arguments(a.clone());
        let bytes = args.marshal_binary().expect("marshal scdata");
        let params: std::collections::HashMap<String, String> = {
            let mut p = std::collections::HashMap::new();
            if let Some(f) = self.sc.functions.get(entrypoint) {
                for fp in &f.params {
                    if let Some(v) = args.get_string(&fp.name) { p.insert(fp.name.clone(), v); }
                }
            }
            p
        };
        let mut state = dero_crypto::dvm::SharedState::new(&self.scid, &self.blid, &self.txid, &[0u8; 33], self.bl_height, self.bl_height, self.bl_height);
        seed_store_from_tree(&mut state.store, &self.data_tree);
        let r = dero_crypto::dvm::run_smart_contract(&self.sc, entrypoint, &mut state, &params)
            .expect("read-only query");
        r.value_uint64
    }
}

// SHA256 helper matching the DVM's sha256 builtin (raw 32 bytes as a string).
fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(data);
    hex::encode(h)
}

// Assemble the DERO (zero) asset SCID that SEND_DERO_TO_ADDRESS uses.
fn dero_asset() -> [u8; 32] {
    [0u8; 32]
}

fn addr_bytes(addr: &str) -> [u8; 33] {
    let mut out = [0u8; 33];
    out.copy_from_slice(&addr.as_bytes()[..33]);
    out
}

#[test]
fn atomic_swap_full_lifecycle() {
    let preimage = b"relay-atomic-preimage-42";
    let hashlock = sha256_hex(preimage);
    let funder = gen_addr();     // stored maker / funder
    let taker = neg_g_addr();    // stored taker (counterparty payout recipient)

    // CreateSwap at height 100, timeout 50 -> expires at 150.
    let mut ctx = Ctx::new(100);
    let ret = ctx.call("CreateSwap", vec![
        ("id".into(), ArgValue::Str("a1".into())),
        ("maker".into(), ArgValue::Str(funder.clone())),
        ("taker".into(), ArgValue::Str(taker.clone())),
        ("sellToken".into(), ArgValue::Str("DERO".into())),
        ("sellAmount".into(), ArgValue::U64(1000)),
        ("buyToken".into(), ArgValue::Str("USDT".into())),
        ("buyAmount".into(), ArgValue::U64(500)),
        ("hashlock".into(), ArgValue::Str(hashlock.clone())),
        ("timeout".into(), ArgValue::U64(50)),
    ], 0);
    assert_eq!(ret, 0, "CreateSwap should succeed");
    assert_eq!(ctx.query_uint64("GetState", "a1"), 0, "state 0 after create");
    assert_eq!(ctx.query_string("GetMaker", "a1"), funder, "maker round-trips");
    assert_eq!(ctx.query_string("GetTaker", "a1"), taker, "taker round-trips");

    // Fund with insufficient incoming -> reject, no payout
    let ret = ctx.call("Fund", vec![
        ("id".into(), ArgValue::Str("a1".into())),
        ("funder".into(), ArgValue::Str(funder.clone())),
    ], 500);
    assert_eq!(ret, 1, "Fund with 500 (< sellAmount 1000) must reject");
    assert_eq!(ctx.query_uint64("GetState", "a1"), 0, "state stays 0");
    assert!(ctx.transfers().is_empty(), "no payout on failed fund");

    // Fund OVER the nominal amount (1500 > sellAmount 1000) -> succeeds, and
    // _funded tracks the ACTUAL DEROVALUE (1500), so a full refund/claim
    // returns the over-fund too. (One successful Fund per swap: Fund rejects
    // once state is already 1.)
    let ret = ctx.call("Fund", vec![
        ("id".into(), ArgValue::Str("a1".into())),
        ("funder".into(), ArgValue::Str(funder.clone())),
    ], 1500);
    assert_eq!(ret, 0, "Fund with 1500 should succeed");
    assert_eq!(ctx.query_uint64("GetState", "a1"), 1, "state 1 after fund");
    assert_eq!(ctx.query_uint64("GetFunded", "a1"), 1500, "over-fund captured");
    assert!(ctx.transfers().is_empty(), "funding does not pay out yet");

    // Claim with WRONG preimage -> reject, no payout
    let ret = ctx.call("Claim", vec![
        ("id".into(), ArgValue::Str("a1".into())),
        ("preimage".into(), ArgValue::Str("wrong-preimage".into())),
    ], 0);
    assert_eq!(ret, 1, "Claim with wrong preimage must reject");
    assert_eq!(ctx.query_uint64("GetState", "a1"), 1, "state stays 1");
    assert!(ctx.transfers().is_empty(), "no payout on failed claim");

    // Claim with CORRECT preimage -> settle (state 2) AND pay the taker the
    // funded amount. The payout leg must appear exactly once.
    let ret = ctx.call("Claim", vec![
        ("id".into(), ArgValue::Str("a1".into())),
        ("preimage".into(), ArgValue::Str(String::from_utf8(preimage.to_vec()).unwrap())),
    ], 0);
    assert_eq!(ret, 0, "Claim with correct preimage should succeed");
    assert_eq!(ctx.query_uint64("GetState", "a1"), 2, "state 2 after claim");
    assert_eq!(ctx.transfers().len(), 1, "exactly one payout transfer on claim");
    assert_eq!(ctx.transfers()[0].asset, dero_asset(), "payout asset is DERO");
    assert_eq!(ctx.transfers()[0].address, addr_bytes(&taker), "payout goes to taker");
    assert_eq!(ctx.transfers()[0].amount, 1500, "payout = actual funded amount");

    // Refund on a settled swap -> reject (state != 1), no extra payout
    let ret = ctx.call("Refund", vec![
        ("id".into(), ArgValue::Str("a1".into())),
        ("funder".into(), ArgValue::Str(funder.clone())),
    ], 0);
    assert_eq!(ret, 1, "Refund on settled swap must reject");
    assert_eq!(ctx.transfers().len(), 1, "no refund transfer on settled swap");
}

#[test]
fn atomic_swap_refund_after_timeout() {
    let preimage = b"another-preimage-77";
    let hashlock = sha256_hex(preimage);
    let funder = gen_addr();
    let taker = neg_g_addr();

    // Funded but never claimed; timeout expires; the funder (and ONLY the
    // funder) can refund, paying the locked value back to the funder.
    let mut ctx = Ctx::new(100); // CreateSwap timeout 10 -> expires at 110
    let ret = ctx.call("CreateSwap", vec![
        ("id".into(), ArgValue::Str("a2".into())),
        ("maker".into(), ArgValue::Str(funder.clone())),
        ("taker".into(), ArgValue::Str(taker.clone())),
        ("sellToken".into(), ArgValue::Str("DERO".into())),
        ("sellAmount".into(), ArgValue::U64(999)),
        ("buyToken".into(), ArgValue::Str("USDT".into())),
        ("buyAmount".into(), ArgValue::U64(499)),
        ("hashlock".into(), ArgValue::Str(hashlock)),
        ("timeout".into(), ArgValue::U64(10)),
    ], 0);
    assert_eq!(ret, 0);

    // Fund at height 100 with an over-fund (1200 > 999) to prove the refund
    // returns the ACTUAL locked amount, not the nominal sellAmount.
    let ret = ctx.call("Fund", vec![
        ("id".into(), ArgValue::Str("a2".into())),
        ("funder".into(), ArgValue::Str(funder.clone())),
    ], 1200);
    assert_eq!(ret, 0, "fund");
    assert_eq!(ctx.query_uint64("GetState", "a2"), 1);
    assert_eq!(ctx.query_uint64("GetFunded", "a2"), 1200);

    // Refund BEFORE timeout -> reject, no payout
    let ret = ctx.call("Refund", vec![
        ("id".into(), ArgValue::Str("a2".into())),
        ("funder".into(), ArgValue::Str(funder.clone())),
    ], 0);
    assert_eq!(ret, 1, "refund before timeout must reject");
    assert_eq!(ctx.query_uint64("GetState", "a2"), 1);
    assert!(ctx.transfers().is_empty(), "no payout on early refund");

    // Advance chain past timeout, refund -> state 3, pay the funder.
    ctx.bl_height = 120;
    let ret = ctx.call("Refund", vec![
        ("id".into(), ArgValue::Str("a2".into())),
        ("funder".into(), ArgValue::Str(funder.clone())),
    ], 0);
    assert_eq!(ret, 0, "refund after timeout should succeed");
    assert_eq!(ctx.query_uint64("GetState", "a2"), 3, "state 3 after refund");
    assert_eq!(ctx.transfers().len(), 1, "exactly one payout transfer on refund");
    assert_eq!(ctx.transfers()[0].asset, dero_asset(), "refund asset is DERO");
    assert_eq!(ctx.transfers()[0].address, addr_bytes(&funder), "refund goes to funder");
    assert_eq!(ctx.transfers()[0].amount, 1200, "refund returns actual funded amount");

    // Claim after refund -> reject, no extra payout
    let ret = ctx.call("Claim", vec![
        ("id".into(), ArgValue::Str("a2".into())),
        ("preimage".into(), ArgValue::Str(String::from_utf8(preimage.to_vec()).unwrap())),
    ], 0);
    assert_eq!(ret, 1, "claim after refund must reject");
    assert_eq!(ctx.transfers().len(), 1, "no payout on claim after refund");
}

#[test]
fn atomic_swap_refund_is_funder_only() {
    let preimage = b"griefing-preimage-9";
    let hashlock = sha256_hex(preimage);
    let funder = gen_addr();
    let taker = neg_g_addr();
    let attacker = x_addr(2); // a third party who is NOT the funder

    let mut ctx = Ctx::new(100); // timeout 10 -> expires at 110
    let ret = ctx.call("CreateSwap", vec![
        ("id".into(), ArgValue::Str("a3".into())),
        ("maker".into(), ArgValue::Str(funder.clone())),
        ("taker".into(), ArgValue::Str(taker.clone())),
        ("sellToken".into(), ArgValue::Str("DERO".into())),
        ("sellAmount".into(), ArgValue::U64(500)),
        ("buyToken".into(), ArgValue::Str("USDT".into())),
        ("buyAmount".into(), ArgValue::U64(250)),
        ("hashlock".into(), ArgValue::Str(hashlock)),
        ("timeout".into(), ArgValue::U64(10)),
    ], 0);
    assert_eq!(ret, 0);

    let ret = ctx.call("Fund", vec![
        ("id".into(), ArgValue::Str("a3".into())),
        ("funder".into(), ArgValue::Str(funder.clone())),
    ], 500);
    assert_eq!(ret, 0, "fund");

    // After timeout, an attacker (wrong funder) cannot trigger the refund.
    ctx.bl_height = 120;
    let ret = ctx.call("Refund", vec![
        ("id".into(), ArgValue::Str("a3".into())),
        ("funder".into(), ArgValue::Str(attacker)),
    ], 0);
    assert_eq!(ret, 1, "refund by non-funder must reject");
    assert_eq!(ctx.query_uint64("GetState", "a3"), 1, "state stays funded");
    assert!(ctx.transfers().is_empty(), "no payout to attacker");

    // The real funder can still refund and recovers the value.
    let ret = ctx.call("Refund", vec![
        ("id".into(), ArgValue::Str("a3".into())),
        ("funder".into(), ArgValue::Str(funder.clone())),
    ], 0);
    assert_eq!(ret, 0, "funder refund succeeds");
    assert_eq!(ctx.transfers().len(), 1);
    assert_eq!(ctx.transfers()[0].address, addr_bytes(&funder), "payout to funder");
    assert_eq!(ctx.transfers()[0].amount, 500);
}
