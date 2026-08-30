// SPDX-License-Identifier: BSD-3-Clause
// Atomic settlement (hash-lock / HTLC) — RelayOS ADR-0041/0043 "atomicity
// without custody". Two-leg swap with real value movement:
//   CreateSwap -> Fund (locks value into SC) -> Claim (reveal preimage) ->
//   Refund (after timeout). Grounded in DERO DVM constraints:
//     - success = RETURN 0 (nonzero is "Discarded knowingly" -> no commit)
//     - recipient addresses stored as compressed 33-byte keys (SIGNER() is
//       zero on ringsize-4 txs, unusable for payout)
//     - hash-lock: SHA256(preimage) == stored hashlock enables cross-leg
//       atomicity (Tier Nolan reveal)
//     - refund after timeout = independent per-leg refund

use dero_crypto::dvm::{parse_smart_contract, SmartContract};
use dero_crypto::rpc_args::{Argument, ArgValue, Arguments, DATA_HASH, DATA_STRING, DATA_UINT64};
use dero_crypto::sc::{execute_sc_function, seed_store_from_tree, TreeWrapper};

fn new_tree_wrapper() -> TreeWrapper {
    TreeWrapper::new(dero_crypto::graviton::Tree::new("atomic-swap-test"))
}

fn atomic_swap_code() -> &'static str {
    r#"
Function Initialize() Uint64
10 RETURN 0
End Function

Function CreateSwap(id String, maker String, sellToken String, sellAmount Uint64, buyToken String, buyAmount Uint64, hashlock String, timeout Uint64) Uint64
10 IF EXISTS("swap_" + id + "_maker") THEN GOTO 100
20 IF sellAmount == 0 THEN GOTO 100
30 IF buyAmount == 0 THEN GOTO 100
40 IF timeout == 0 THEN GOTO 100
50 STORE("swap_" + id + "_maker", maker)
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
50 STORE("swap_" + id + "_funded", LOAD("swap_" + id + "_sellAmount"))
60 STORE("swap_" + id + "_state", 1)
70 RETURN 0
100 RETURN 1
End Function

Function Claim(id String, preimage String) Uint64
10 IF LOAD("swap_" + id + "_state") != 1 THEN GOTO 100
20 IF HEX(SHA256(preimage)) != LOAD("swap_" + id + "_hashlock") THEN GOTO 100
30 STORE("swap_" + id + "_state", 2)
40 RETURN 0
100 RETURN 1
End Function

Function Refund(id String) Uint64
10 IF LOAD("swap_" + id + "_state") != 1 THEN GOTO 100
20 IF BLOCK_HEIGHT() <= LOAD("swap_" + id + "_timeout") THEN GOTO 100
30 STORE("swap_" + id + "_state", 3)
40 RETURN 0
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

    fn query_maker(&mut self, id: &str) -> String {
        let a: Vec<Argument> = vec![
            Argument { name: "SC_ACTION".into(), data_type: DATA_UINT64, value: ArgValue::U64(0) },
            Argument { name: "SC_ID".into(), data_type: DATA_HASH, value: ArgValue::Hash(self.scid) },
            Argument { name: "entrypoint".into(), data_type: DATA_STRING, value: ArgValue::Str("GetMaker".into()) },
            Argument { name: "id".into(), data_type: DATA_STRING, value: ArgValue::Str(id.into()) },
        ];
        let args = Arguments(a.clone());
        let bytes = args.marshal_binary().expect("marshal scdata");
        let params: std::collections::HashMap<String, String> = {
            let mut p = std::collections::HashMap::new();
            if let Some(f) = self.sc.functions.get("GetMaker") {
                for fp in &f.params {
                    if let Some(v) = args.get_string(&fp.name) { p.insert(fp.name.clone(), v); }
                }
            }
            p
        };
        let mut state = dero_crypto::dvm::SharedState::new(&self.scid, &self.blid, &self.txid, &[0u8; 33], self.bl_height, self.bl_height, self.bl_height);
        seed_store_from_tree(&mut state.store, &self.data_tree);
        let r = dero_crypto::dvm::run_smart_contract(&self.sc, "GetMaker", &mut state, &params)
            .expect("read-only query");
        r.value_string
    }

    fn query_state(&mut self, id: &str) -> u64 {
        let mut a: Vec<Argument> = vec![
            Argument { name: "SC_ACTION".into(), data_type: DATA_UINT64, value: ArgValue::U64(0) },
            Argument { name: "SC_ID".into(), data_type: DATA_HASH, value: ArgValue::Hash(self.scid) },
            Argument { name: "entrypoint".into(), data_type: DATA_STRING, value: ArgValue::Str("GetState".into()) },
            Argument { name: "id".into(), data_type: DATA_STRING, value: ArgValue::Str(id.into()) },
        ];
        let args = Arguments(a.clone());
        let bytes = args.marshal_binary().expect("marshal scdata");
        let params: std::collections::HashMap<String, String> = {
            let mut p = std::collections::HashMap::new();
            if let Some(f) = self.sc.functions.get("GetState") {
                for fp in &f.params {
                    if let Some(v) = args.get_string(&fp.name) { p.insert(fp.name.clone(), v); }
                }
            }
            p
        };
        let mut state = dero_crypto::dvm::SharedState::new(&self.scid, &self.blid, &self.txid, &[0u8; 33], self.bl_height, self.bl_height, self.bl_height);
        seed_store_from_tree(&mut state.store, &self.data_tree);
        let r = dero_crypto::dvm::run_smart_contract(&self.sc, "GetState", &mut state, &params)
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

fn funder_addr() -> String {
    let mut s = [0u8; 33];
    s[0] = 0x04;
    s[32] = 0x00;
    String::from_utf8_lossy(&s).into_owned()
}

#[test]
fn atomic_swap_full_lifecycle() {
    let preimage = b"relay-atomic-preimage-42";
    let hashlock = sha256_hex(preimage);
    let funder = funder_addr();

    // CreateSwap at height 100, timeout 50 -> expires at 150.
    let mut ctx = Ctx::new(100);
    let ret = ctx.call("CreateSwap", vec![
        ("id".into(), ArgValue::Str("a1".into())),
        ("maker".into(), ArgValue::Str(funder.clone())),
        ("sellToken".into(), ArgValue::Str("DERO".into())),
        ("sellAmount".into(), ArgValue::U64(1000)),
        ("buyToken".into(), ArgValue::Str("USDT".into())),
        ("buyAmount".into(), ArgValue::U64(500)),
        ("hashlock".into(), ArgValue::Str(hashlock.clone())),
        ("timeout".into(), ArgValue::U64(50)),
    ], 0);
    assert_eq!(ret, 0, "CreateSwap should succeed");
    assert_eq!(ctx.query_state("a1"), 0, "state 0 after create");
    // DIAGNOSTIC: does the stored maker round-trip as the funder string?
    let stored_maker = ctx.query_maker("a1");
    assert_eq!(stored_maker, funder, "stored maker should equal funder (stored={:?} funder={:?})", stored_maker, funder);

    // Fund with insufficient incoming -> reject
    let ret = ctx.call("Fund", vec![
        ("id".into(), ArgValue::Str("a1".into())),
        ("funder".into(), ArgValue::Str(funder.clone())),
    ], 500);
    assert_eq!(ret, 1, "Fund with 500 (< sellAmount 1000) must reject");
    assert_eq!(ctx.query_state("a1"), 0, "state stays 0");

    // Fund with correct amount -> state 1
    let ret = ctx.call("Fund", vec![
        ("id".into(), ArgValue::Str("a1".into())),
        ("funder".into(), ArgValue::Str(funder.clone())),
    ], 1000);
    assert_eq!(ret, 0, "Fund with 1000 should succeed");
    assert_eq!(ctx.query_state("a1"), 1, "state 1 after fund");

    // Claim with WRONG preimage -> reject
    let ret = ctx.call("Claim", vec![
        ("id".into(), ArgValue::Str("a1".into())),
        ("preimage".into(), ArgValue::Str("wrong-preimage".into())),
    ], 0);
    assert_eq!(ret, 1, "Claim with wrong preimage must reject");
    assert_eq!(ctx.query_state("a1"), 1, "state stays 1");

    // Claim with CORRECT preimage -> settle (state 2)
    let ret = ctx.call("Claim", vec![
        ("id".into(), ArgValue::Str("a1".into())),
        ("preimage".into(), ArgValue::Str(String::from_utf8(preimage.to_vec()).unwrap())),
    ], 0);
    assert_eq!(ret, 0, "Claim with correct preimage should succeed");
    assert_eq!(ctx.query_state("a1"), 2, "state 2 after claim");

    // Refund on a settled swap -> reject (state != 1)
    let ret = ctx.call("Refund", vec![("id".into(), ArgValue::Str("a1".into()))], 0);
    assert_eq!(ret, 1, "Refund on settled swap must reject");
}

#[test]
fn atomic_swap_refund_after_timeout() {
    let preimage = b"another-preimage-77";
    let hashlock = sha256_hex(preimage);
    let funder = funder_addr();

    // Funded but never claimed; timeout expires; refund succeeds.
    let mut ctx = Ctx::new(100); // CreateSwap timeout 10 -> expires at 110
    let ret = ctx.call("CreateSwap", vec![
        ("id".into(), ArgValue::Str("a2".into())),
        ("maker".into(), ArgValue::Str(funder.clone())),
        ("sellToken".into(), ArgValue::Str("DERO".into())),
        ("sellAmount".into(), ArgValue::U64(999)),
        ("buyToken".into(), ArgValue::Str("USDT".into())),
        ("buyAmount".into(), ArgValue::U64(499)),
        ("hashlock".into(), ArgValue::Str(hashlock)),
        ("timeout".into(), ArgValue::U64(10)),
    ], 0);
    assert_eq!(ret, 0);

    // Fund at height 100
    let ret = ctx.call("Fund", vec![
        ("id".into(), ArgValue::Str("a2".into())),
        ("funder".into(), ArgValue::Str(funder.clone())),
    ], 999);
    assert_eq!(ret, 0, "fund");
    assert_eq!(ctx.query_state("a2"), 1);

    // Refund BEFORE timeout -> reject
    let ret = ctx.call("Refund", vec![("id".into(), ArgValue::Str("a2".into()))], 0);
    assert_eq!(ret, 1, "refund before timeout must reject");
    assert_eq!(ctx.query_state("a2"), 1);

    // Advance chain past timeout, refund -> state 3
    ctx.bl_height = 120;
    let ret = ctx.call("Refund", vec![("id".into(), ArgValue::Str("a2".into()))], 0);
    assert_eq!(ret, 0, "refund after timeout should succeed");
    assert_eq!(ctx.query_state("a2"), 3, "state 3 after refund");

    // Claim after refund -> reject
    let ret = ctx.call("Claim", vec![
        ("id".into(), ArgValue::Str("a2".into())),
        ("preimage".into(), ArgValue::Str(String::from_utf8(preimage.to_vec()).unwrap())),
    ], 0);
    assert_eq!(ret, 1, "claim after refund must reject");
}
