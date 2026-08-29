// SPDX-License-Identifier: BSD-3-Clause
// DEX escrow lifecycle — the Private Settlement limit-order SC (Phase 1).
//
// Drives the FULL lifecycle through the node's real SC-execution path
// (sc::execute_sc_function) with a persistent data tree, exercising:
//   install(Initialize) -> CreateSwap -> GetSwap -> AcceptSwap -> CancelSwap
// This validates the multi-string-arg fix + STORE/LOAD persistence + the
// BLOCK_HEIGHT()/SIGNER() intrinsics together (the escrow.s that previously
// failed with "trailing tokens" on CreateSwap).

use dero_crypto::dvm::{parse_smart_contract, SmartContract};
use dero_crypto::rpc_args::{Argument, ArgValue, Arguments, DATA_HASH, DATA_STRING, DATA_UINT64};
use dero_crypto::sc::{execute_sc_function, TreeWrapper};

// A minimal graviton-backed tree wrapper for SC data (mirrors what the node
// builds around the SC data tree).
fn new_tree_wrapper() -> TreeWrapper {
    TreeWrapper::new(dero_crypto::graviton::Tree::new("escrow-test"))
}

fn escrow_code() -> &'static str {
    r#"
Function Initialize() Uint64
10 RETURN 0
End Function

Function CreateSwap(id String, sellToken String, sellAmount Uint64, buyToken String, buyAmount Uint64, maker String, timeout Uint64) Uint64
10 IF EXISTS("swap_" + id + "_maker") THEN GOTO 100
20 IF sellAmount == 0 THEN GOTO 100
30 IF buyAmount == 0 THEN GOTO 100
40 STORE("swap_" + id + "_maker", maker)
50 STORE("swap_" + id + "_sellToken", sellToken)
60 STORE("swap_" + id + "_sellAmount", sellAmount)
70 STORE("swap_" + id + "_buyToken", buyToken)
80 STORE("swap_" + id + "_buyAmount", buyAmount)
90 STORE("swap_" + id + "_state", 0)
95 STORE("swap_" + id + "_timeout", BLOCK_HEIGHT() + timeout)
96 RETURN 0
100 RETURN 1
End Function

Function AcceptSwap(id String, taker String) Uint64
10 IF LOAD("swap_" + id + "_state") != 0 THEN GOTO 100
20 IF SIGNER() == LOAD("swap_" + id + "_maker") THEN GOTO 100
30 STORE("swap_" + id + "_taker", taker)
40 STORE("swap_" + id + "_state", 1)
50 RETURN 0
100 RETURN 1
End Function

Function CancelSwap(id String) Uint64
10 IF LOAD("swap_" + id + "_state") == 0 THEN GOTO 40
20 IF LOAD("swap_" + id + "_state") == 1 THEN GOTO 60
30 GOTO 100
40 IF SIGNER() == LOAD("swap_" + id + "_maker") THEN GOTO 50
45 GOTO 100
50 STORE("swap_" + id + "_state", 3)
55 RETURN 0
60 IF BLOCK_HEIGHT() > LOAD("swap_" + id + "_timeout") THEN GOTO 70
65 GOTO 100
70 STORE("swap_" + id + "_state", 3)
75 RETURN 0
100 RETURN 1
End Function

Function GetSwap(id String) Uint64
10 IF EXISTS("swap_" + id + "_maker") THEN GOTO 20
15 RETURN 0
20 RETURN 1
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
    fn new() -> Self {
        let code = escrow_code();
        let sc = parse_smart_contract(code).expect("parse escrow.s");
        // install: scid = a fixed id (the node uses the install txid)
        let scid = [0x0e; 32];
        Ctx {
            data_tree: new_tree_wrapper(),
            sc_meta: new_tree_wrapper(),
            scid,
            sc,
            bl_height: 100,
            blid: [0xaa; 32],
            txid: [0xbb; 32],
        }
    }

    fn call(&mut self, entrypoint: &str, args: Vec<(String, ArgValue)>, signer: &[u8; 33]) -> u64 {
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
        let incoming = std::collections::HashMap::new();
        self.txid[0] = self.txid[0].wrapping_add(1);
        match execute_sc_function(
            &mut self.sc_meta, &mut self.data_tree, &self.scid,
            self.bl_height, self.bl_height, self.bl_height, &self.blid, &self.txid,
            &self.sc, entrypoint, 0, signer, &incoming, &bytes, 0,
        ) {
            Ok((ret, _gas)) => ret,
            // A nonzero entrypoint return is "Discarded knowingly" — the SC
            // call is a no-op (no state committed), which is how DERO rejects
            // a call (e.g. double-accept, cancel-before-timeout). escrow.s
            // returns 1 for every rejection path.
            Err(e) if e == "Discarded knowingly" => 1,
            Err(e) => panic!("execute_sc_function: {e}"),
        }
    }

    fn query(&mut self, entrypoint: &str, args: Vec<(String, ArgValue)>) -> u64 {
        // read-only evaluation (GetSwap etc.) — mirrors an off-chain SC read,
        // which does NOT go through the committing execute_sc_function (that
        // requires RETURN 0 and would reject a query that returns 1).
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
        let scdata = Arguments(a.clone());
        let args = Arguments(a);
        let bytes = args.marshal_binary().expect("marshal scdata");
        let params: std::collections::HashMap<String, String> = {
            let mut p = std::collections::HashMap::new();
            if let Some(f) = self.sc.functions.get(entrypoint) {
                for fp in &f.params {
                    match (&fp.vtype, fp.name.as_str()) {
                        (dero_crypto::dvm::Vtype::Uint64, _) => {
                            if let Some(v) = scdata.get_uint64(&fp.name) { p.insert(fp.name.clone(), format!("{v}")); }
                        }
                        (dero_crypto::dvm::Vtype::String, _) => {
                            if let Some(v) = scdata.get_string(&fp.name) { p.insert(fp.name.clone(), v); }
                        }
                        _ => {}
                    }
                }
            }
            p
        };
        // seed a fresh state from the committed data tree, then run read-only
        let mut state = dero_crypto::dvm::SharedState::new(&self.scid, &self.blid, &self.txid, &[0u8; 33], self.bl_height, self.bl_height, self.bl_height);
        dero_crypto::sc::seed_store_from_tree(&mut state.store, &self.data_tree);
        let r = dero_crypto::dvm::run_smart_contract(&self.sc, entrypoint, &mut state, &params)
            .expect("read-only query");
        r.value_uint64
    }
}

fn maker_signer() -> [u8; 33] {
    let mut s = [0u8; 33];
    s[0] = 0x02;
    s[32] = 0x00;
    s
}

fn taker_signer() -> [u8; 33] {
    let mut s = [0u8; 33];
    s[0] = 0x03;
    s[32] = 0x01;
    s
}

// The maker "address" the escrow stores/compares is the raw signer's
// lossy-string, because DVM SIGNER() returns the raw 33-byte key as a string
// and the escrow checks `SIGNER() == LOAD("swap_..._maker")`.
fn maker_addr() -> String {
    String::from_utf8_lossy(&maker_signer()).into_owned()
}

#[test]
fn escrow_full_lifecycle() {
    let mut ctx = Ctx::new();
    let maker = maker_signer();
    let taker = taker_signer();

    // 1. CreateSwap by maker -> RETURN 0 = success (STOREs commit)
    let ret = ctx.call("CreateSwap", vec![
        ("id".into(), ArgValue::Str("swap1".into())),
        ("sellToken".into(), ArgValue::Str("DERO".into())),
        ("sellAmount".into(), ArgValue::U64(1000)),
        ("buyToken".into(), ArgValue::Str("USDT".into())),
        ("buyAmount".into(), ArgValue::U64(500)),
        ("maker".into(), ArgValue::Str(maker_addr())),
        ("timeout".into(), ArgValue::U64(100)),
    ], &maker);
    assert_eq!(ret, 0, "CreateSwap should succeed (RETURN 0)");

    // 2. GetSwap exists now (read-only query)
    let ret = ctx.query("GetSwap", vec![("id".into(), ArgValue::Str("swap1".into()))]);
    assert_eq!(ret, 1, "GetSwap should find the swap");

    // 3. AcceptSwap by taker (not the maker) -> succeeds, state -> 1
    let ret = ctx.call("AcceptSwap", vec![
        ("id".into(), ArgValue::Str("swap1".into())),
        ("taker".into(), ArgValue::Str("deto1qyh7q8h86...".into())),
    ], &taker);
    assert_eq!(ret, 0, "AcceptSwap by non-maker taker should succeed (RETURN 0)");

    // 4. AcceptSwap AGAIN -> state already 1, so it rejects (RETURN 1)
    let ret = ctx.call("AcceptSwap", vec![
        ("id".into(), ArgValue::Str("swap1".into())),
        ("taker".into(), ArgValue::Str("deto1qyh7q8h86...".into())),
    ], &taker);
    assert_eq!(ret, 1, "second AcceptSwap must reject (state != 0)");

    // 5. CancelSwap after accept: state==1 -> needs timeout to pass.
    //    At bl_height=100 with timeout=100 stored as BLOCK_HEIGHT()+timeout=200,
    //    BLOCK_HEIGHT()>200 is false -> reject (state stays 1).
    let ret = ctx.call("CancelSwap", vec![("id".into(), ArgValue::Str("swap1".into()))], &taker);
    assert_eq!(ret, 1, "CancelSwap before timeout on an accepted swap must reject");

    // 6. Fresh swap created + cancelled by the maker before accept (state 0 -> cancel path 50).
    let ret = ctx.call("CreateSwap", vec![
        ("id".into(), ArgValue::Str("swap2".into())),
        ("sellToken".into(), ArgValue::Str("DERO".into())),
        ("sellAmount".into(), ArgValue::U64(777)),
        ("buyToken".into(), ArgValue::Str("USDT".into())),
        ("buyAmount".into(), ArgValue::U64(333)),
        ("maker".into(), ArgValue::Str(maker_addr())),
        ("timeout".into(), ArgValue::U64(50)),
    ], &maker);
    assert_eq!(ret, 0, "CreateSwap #2 should succeed");

    let ret = ctx.call("CancelSwap", vec![("id".into(), ArgValue::Str("swap2".into()))], &maker);
    assert_eq!(ret, 0, "maker cancels own pre-accept swap -> state 3, RETURN 0");

    // 7. Non-maker cannot cancel the pre-accept swap.
    let ret = ctx.call("CreateSwap", vec![
        ("id".into(), ArgValue::Str("swap3".into())),
        ("sellToken".into(), ArgValue::Str("DERO".into())),
        ("sellAmount".into(), ArgValue::U64(9)),
        ("buyToken".into(), ArgValue::Str("BTC".into())),
        ("buyAmount".into(), ArgValue::U64(1)),
        ("maker".into(), ArgValue::Str(maker_addr())),
        ("timeout".into(), ArgValue::U64(10)),
    ], &maker);
    assert_eq!(ret, 0);
    let ret = ctx.call("CancelSwap", vec![("id".into(), ArgValue::Str("swap3".into()))], &taker);
    assert_eq!(ret, 1, "non-maker cannot cancel a pre-accept swap");
}
