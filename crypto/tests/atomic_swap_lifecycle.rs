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

use ark_ec::PrimeGroup;
use dero_crypto::balance_serdes::NonceBalance;
use dero_crypto::curve::{be32_to_bigint, decode_compressed};
use dero_crypto::dvm::{parse_smart_contract, SmartContract};
use dero_crypto::elgamal::ElGamal;
use dero_crypto::hash_to_point::base_g;
use dero_crypto::rpc_args::{Argument, ArgValue, Arguments, DATA_HASH, DATA_STRING, DATA_UINT64};
use dero_crypto::sc::{
    execute_sc_function, load_sc_asset_value, process_external, sanity_check_external_transfers,
    seed_store_from_tree, Snapshot, TreeWrapper, TransferExternal,
};

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
        let _bytes = args.marshal_binary().expect("marshal scdata");
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
        let _bytes = args.marshal_binary().expect("marshal scdata");
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

    /// Run the SHIPPED chain post-call external-processing (chain.rs
    /// process_transaction_sc's tail — sanity_check_external_transfers then
    /// process_external) over the SEND_* transfers the last call flushed.
    /// This is the seam that DEBITS the SC's stored value and CREDITS the
    /// recipients' real balance-tree entries (an ElGamal `.plus` homomorphic
    /// add into the NonceBalance ciphertext). Mirrors add_complete_block's
    /// SC execute phase.
    fn settle_external(&mut self, balance_tree: &mut dero_crypto::graviton::Tree) {
        if self.data_tree.transfers.is_empty() {
            return;
        }
        let mut cache: std::collections::HashMap<[u8; 32], dero_crypto::graviton::Tree> =
            std::collections::HashMap::new();
        let ss = Snapshot { trees: std::collections::HashMap::new() };
        sanity_check_external_transfers(&mut self.data_tree, balance_tree, &self.scid)
            .expect("sanity_check_external_transfers must pass");
        process_external(
            &mut cache, &ss, balance_tree, &self.scid, &mut self.data_tree, &mut self.sc_meta,
        );
        assert!(self.data_tree.transfers.is_empty(), "process_external consumes transfers");
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

fn u64_to_32(v: u64) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[24..32].copy_from_slice(&v.to_be_bytes());
    b
}

/// Register an account in the balance tree exactly the way the wallet/node does —
/// a NonceBalance{ nonce_height, balance:ElGamal::commit(public_key, value, r) }
/// under the account's compressed 33-byte key. Returns the committed ciphertext
/// so tests can assert the tree entry changed (via .plus) after a payout.

fn register_account(tree: &mut dero_crypto::graviton::Tree, addr: &str, balance: u64) -> ElGamal {
    let ab = addr_bytes(addr);
    let pk = decode_compressed(&ab).expect("register: addr must be a valid curve point");
    let mut r = [0u8; 32];
    r[31] = 9;
    let cm = ElGamal::commit(&pk, &u64_to_32(balance), &r);
    let nb = NonceBalance { nonce_height: 0, balance:cm.clone() };
    tree.put(&ab, &nb.serialize());
    cm
}

/// Read the current balance-tree ciphertext for an account (the committed
/// ElGamal). Panics if the account isn't registered.
fn read_balance(tree: &dero_crypto::graviton::Tree, addr: &str) -> ElGamal {
    let ab = addr_bytes(addr);
    let raw = tree.get(&ab.to_vec()).expect("account registered in balance tree");
    NonceBalance::deserialize(&raw).expect("nonce deserialize").balance
}

/// Assert an account's balance-tree ciphertext grew by exactly `amount` DERO
/// (left += amount*G, right unchanged) — the homomorphic `.plus` the shipped
/// process_external uses. `before` is the pre-settle ciphertext.
fn assert_credited(tree: &dero_crypto::graviton::Tree, addr: &str, before: &ElGamal, amount: u64, what: &str) {
    let after = read_balance(tree, addr);
    let g = base_g();
    assert_eq!(
        after.left - before.left,
        g.mul_bigint(be32_to_bigint(&u64_to_32(amount))),
        "{what}: balance-tree entry credited exactly {amount}"
    );
    assert_eq!(after.right, before.right, "{what}: homomorphic right unchanged");
}

/// Assert an account's balance-tree ciphertext is byte-identical to `before`
/// (no value moved in or out).
fn assert_untouched(tree: &dero_crypto::graviton::Tree, addr: &str, before: &ElGamal, what: &str) {
    let after = read_balance(tree, addr);
    assert_eq!(after.left, before.left, "{what}: left unchanged");
    assert_eq!(after.right, before.right, "{what}: right unchanged");
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

#[test]
fn send_value_movement_credits_real_balance_tree() {
    let funder = gen_addr();
    let taker = neg_g_addr();
    let init = 50_000u64;
    let mut balance_tree = dero_crypto::graviton::Tree::new("swap-value-tree");
    let funder_before = register_account(&mut balance_tree,&funder,init);
    let taker_before = register_account(&mut balance_tree,&taker,init);

    // The payout emits the 33-byte compressed key as the destination; that
    // exact key must already be REGISTERED in the balance tree (mirrors a real
    // wallet's account). Here we assert the tree holds the committed ciphertext.

    {
        let ab = addr_bytes(&taker);
        let raw = balance_tree.get(&ab.to_vec()).expect("taker registered in balance tree");
        let saved = NonceBalance::deserialize(&raw).expect("nonce deserialize");
        assert_eq!(saved.balance.clone().left, taker_before.clone().left);
    }

    let preimage = b"value-movement-preimage-1";
    let hashlock = sha256_hex(preimage);
    let mut ctx = Ctx::new(100);
    assert_eq!(
        ctx.call("CreateSwap", vec![
            ("id".into(), ArgValue::Str("v1".into())),
            ("maker".into(), ArgValue::Str(funder.clone())),
            ("taker".into(), ArgValue::Str(taker.clone())),
            ("sellToken".into(), ArgValue::Str("DERO".into())),
            ("sellAmount".into(), ArgValue::U64(1000)),
            ("buyToken".into(), ArgValue::Str("USDT".into())),
            ("buyAmount".into(), ArgValue::U64(500)),
            ("hashlock".into(), ArgValue::Str(hashlock)),
            ("timeout".into(), ArgValue::U64(50)),
        ], 0),
        0,
        "create"
    );

    // Fund 1500 DERO in -> the SC value tree now holds 1500 (execute_sc_function
    // credits incoming into the SC's stored asset value; DEROVALUE() reads it).
    assert_eq!(
        ctx.call(
            "Fund",
            vec![
                ("id".into(), ArgValue::Str("v1".into())),
                ("funder".into(), ArgValue::Str(funder.clone())),
            ],
            1500,
        ),
        0,
        "fund"
    );
    assert_eq!(
        load_sc_asset_value(&ctx.data_tree, &ctx.scid, &dero_asset()),
        1500,
        "SC value tree holds the funded DERO"
    );

    // Claim -> flush ONE payout transfer of 1500 to the taker
     assert_eq!(
        ctx.call(
            "Claim",
            vec![
                ("id".into(), ArgValue::Str("v1".into())),
                (
                    "preimage".into(),
                    ArgValue::Str(String::from_utf8(preimage.to_vec()).unwrap()),
                ),
            ],
            0,
        ),
        0,
        "claim"
    );
    assert_eq!(ctx.transfers().len(), 1, "one payout transfer on claim");

    // Before the chain's settlement phase, the taker's balance-tree entry is untouched
     {
        let ab = addr_bytes(&taker);
        let raw = balance_tree.get(&ab.to_vec()).expect("taker registered");
        let nb = NonceBalance::deserialize(&raw).expect("nonce");
        assert_eq!(nb.balance.left, taker_before.clone().left, "payout not yet credited");
    }

    // THE SHIPPED post-call settlement seam (add_complete_block's execute phase):
    // sanity_check_external_transfers debits the SC's stored value, then
    // process_external CREDITS the recipient's balance-tree ciphertext via .plus.

    ctx.settle_external(&mut balance_tree);
    // SC DERO debited back to 0
    assert_eq!(
        load_sc_asset_value(&ctx.data_tree, &ctx.scid, &dero_asset()),
        0,
        "SC debited the full funded value on settle"
    );

    // taker's REAL balance-tree entry now carries +1500 (left += 1500*G, right unchanged — the exact `.plus` crediting the shipped seam uses).
     {
        let ab = addr_bytes(&taker);
        let raw = balance_tree.get(&ab.to_vec()).expect("taker registered");
        let nb = NonceBalance::deserialize(&raw).expect("nonce");
        let g = base_g();
        assert_eq!(
            nb.balance.left - taker_before.clone().left,
            g.mul_bigint(be32_to_bigint(&u64_to_32(1500))),
            "taker balance tree credited exact 1500 via .plus"
        );
        assert_eq!(
            nb.balance.right,
            taker_before.clone().right,
            "homomorphic right unchanged (.plus keeps right)"
        );
    }

    // funder untouched by the payout (their ciphertext is byte-identical).
    {
        let fb = addr_bytes(&funder);
        let raw = balance_tree.get(&fb.to_vec()).expect("funder registered");
        let f = NonceBalance::deserialize(&raw).expect("nonce");
        assert_eq!(f.balance.left, funder_before.clone().left, "funder untouched");
    }
}

/// Hammer: the REFUND leg must move value the same way — SC debited, funder
/// credited, taker untouched. This is the other half of settlement.
#[test]
fn refund_moves_value_back_to_funder() {
    let funder = gen_addr();
    let taker = neg_g_addr();
    let init = 50_000u64;
    let mut balance_tree = dero_crypto::graviton::Tree::new("swap-refund-tree");
    let funder_before = register_account(&mut balance_tree, &funder, init);
    let taker_before = register_account(&mut balance_tree, &taker, init);

    let preimage = b"refund-value-preimage-1";
    let hashlock = sha256_hex(preimage);
    let mut ctx = Ctx::new(100); // timeout 10 -> expires at 110
    assert_eq!(
        ctx.call("CreateSwap", vec![
            ("id".into(), ArgValue::Str("r1".into())),
            ("maker".into(), ArgValue::Str(funder.clone())),
            ("taker".into(), ArgValue::Str(taker.clone())),
            ("sellToken".into(), ArgValue::Str("DERO".into())),
            ("sellAmount".into(), ArgValue::U64(1000)),
            ("buyToken".into(), ArgValue::Str("USDT".into())),
            ("buyAmount".into(), ArgValue::U64(500)),
            ("hashlock".into(), ArgValue::Str(hashlock)),
            ("timeout".into(), ArgValue::U64(10)),
        ], 0),
        0,
        "create"
    );
    assert_eq!(
        ctx.call("Fund", vec![
            ("id".into(), ArgValue::Str("r1".into())),
            ("funder".into(), ArgValue::Str(funder.clone())),
        ], 1200),
        0,
        "fund"
    );
    assert_eq!(
        load_sc_asset_value(&ctx.data_tree, &ctx.scid, &dero_asset()),
        1200,
        "SC holds the funded DERO"
    );

    // Refund BEFORE timeout -> reject, no value moves.
    assert_eq!(
        ctx.call("Refund", vec![
            ("id".into(), ArgValue::Str("r1".into())),
            ("funder".into(), ArgValue::Str(funder.clone())),
        ], 0),
        1,
        "refund before timeout rejects"
    );
    assert!(ctx.transfers().is_empty(), "no payout on early refund");
    assert_untouched(&balance_tree, &funder, &funder_before, "funder before timeout");
    assert_untouched(&balance_tree, &taker, &taker_before, "taker before timeout");

    // Advance past timeout, refund -> SC debited, funder credited.
    ctx.bl_height = 120;
    assert_eq!(
        ctx.call("Refund", vec![
            ("id".into(), ArgValue::Str("r1".into())),
            ("funder".into(), ArgValue::Str(funder.clone())),
        ], 0),
        0,
        "refund after timeout succeeds"
    );
    assert_eq!(ctx.transfers().len(), 1, "one payout on refund");
    assert_eq!(ctx.transfers()[0].address, addr_bytes(&funder), "refund to funder");
    assert_eq!(ctx.transfers()[0].amount, 1200, "refund returns actual funded amount");

    ctx.settle_external(&mut balance_tree);
    assert_eq!(
        load_sc_asset_value(&ctx.data_tree, &ctx.scid, &dero_asset()),
        0,
        "SC debited the full funded value on refund settle"
    );
    assert_credited(&balance_tree, &funder, &funder_before, 1200, "funder refund");
    assert_untouched(&balance_tree, &taker, &taker_before, "taker after refund");
}

/// Hammer: two independent swaps in ONE balance tree must settle without
/// cross-contamination — each taker credited exactly their own payout, each
/// SC debited exactly its own funded value.
#[test]
fn multi_swap_isolation_in_one_balance_tree() {
    let f1 = gen_addr();
    let t1 = neg_g_addr();
    let f2 = x_addr(5);
    let t2 = x_addr(6);
    let init = 50_000u64;
    let mut balance_tree = dero_crypto::graviton::Tree::new("swap-multi-tree");
    let f1_before = register_account(&mut balance_tree, &f1, init);
    let t1_before = register_account(&mut balance_tree, &t1, init);
    let f2_before = register_account(&mut balance_tree, &f2, init);
    let t2_before = register_account(&mut balance_tree, &t2, init);

    let p1 = b"multi-swap-preimage-1";
    let p2 = b"multi-swap-preimage-2";
    let h1 = sha256_hex(p1);
    let h2 = sha256_hex(p2);

    let mut c1 = Ctx::new(100);
    let mut c2 = Ctx::new(100);
    assert_eq!(
        c1.call("CreateSwap", vec![
            ("id".into(), ArgValue::Str("m1".into())),
            ("maker".into(), ArgValue::Str(f1.clone())),
            ("taker".into(), ArgValue::Str(t1.clone())),
            ("sellToken".into(), ArgValue::Str("DERO".into())),
            ("sellAmount".into(), ArgValue::U64(1000)),
            ("buyToken".into(), ArgValue::Str("USDT".into())),
            ("buyAmount".into(), ArgValue::U64(500)),
            ("hashlock".into(), ArgValue::Str(h1)),
            ("timeout".into(), ArgValue::U64(50)),
        ], 0),
        0,
        "create swap 1"
    );
    assert_eq!(
        c2.call("CreateSwap", vec![
            ("id".into(), ArgValue::Str("m2".into())),
            ("maker".into(), ArgValue::Str(f2.clone())),
            ("taker".into(), ArgValue::Str(t2.clone())),
            ("sellToken".into(), ArgValue::Str("DERO".into())),
            ("sellAmount".into(), ArgValue::U64(2000)),
            ("buyToken".into(), ArgValue::Str("USDT".into())),
            ("buyAmount".into(), ArgValue::U64(1000)),
            ("hashlock".into(), ArgValue::Str(h2)),
            ("timeout".into(), ArgValue::U64(50)),
        ], 0),
        0,
        "create swap 2"
    );

    // Fund both: swap1 gets 1500, swap2 gets 2500.
    assert_eq!(
        c1.call("Fund", vec![
            ("id".into(), ArgValue::Str("m1".into())),
            ("funder".into(), ArgValue::Str(f1.clone())),
        ], 1500),
        0,
        "fund swap 1"
    );
    assert_eq!(
        c2.call("Fund", vec![
            ("id".into(), ArgValue::Str("m2".into())),
            ("funder".into(), ArgValue::Str(f2.clone())),
        ], 2500),
        0,
        "fund swap 2"
    );
    assert_eq!(load_sc_asset_value(&c1.data_tree, &c1.scid, &dero_asset()), 1500, "SC1 holds 1500");
    assert_eq!(load_sc_asset_value(&c2.data_tree, &c2.scid, &dero_asset()), 2500, "SC2 holds 2500");

    // Claim swap 1 only. Swap 2 must be completely untouched.
    assert_eq!(
        c1.call("Claim", vec![
            ("id".into(), ArgValue::Str("m1".into())),
            ("preimage".into(), ArgValue::Str(String::from_utf8(p1.to_vec()).unwrap())),
        ], 0),
        0,
        "claim swap 1"
    );
    c1.settle_external(&mut balance_tree);
    assert_credited(&balance_tree, &t1, &t1_before, 1500, "taker1 after claim");
    assert_untouched(&balance_tree, &t2, &t2_before, "taker2 untouched by swap1 claim");
    assert_untouched(&balance_tree, &f1, &f1_before, "funder1 untouched by claim");
    assert_untouched(&balance_tree, &f2, &f2_before, "funder2 untouched by swap1 claim");
    assert_eq!(load_sc_asset_value(&c1.data_tree, &c1.scid, &dero_asset()), 0, "SC1 debited");
    assert_eq!(load_sc_asset_value(&c2.data_tree, &c2.scid, &dero_asset()), 2500, "SC2 still holds 2500");

    // Re-capture the post-swap1 baselines so the swap2 assertions compare
    // against the tree state AFTER swap1 settled (t1 now holds +1500).
    let t1_after_s1 = read_balance(&balance_tree, &t1);
    let t2_after_s1 = read_balance(&balance_tree, &t2);
    let f1_after_s1 = read_balance(&balance_tree, &f1);
    let f2_after_s1 = read_balance(&balance_tree, &f2);

    // Now claim swap 2.
    assert_eq!(
        c2.call("Claim", vec![
            ("id".into(), ArgValue::Str("m2".into())),
            ("preimage".into(), ArgValue::Str(String::from_utf8(p2.to_vec()).unwrap())),
        ], 0),
        0,
        "claim swap 2"
    );
    c2.settle_external(&mut balance_tree);
    assert_credited(&balance_tree, &t2, &t2_after_s1, 2500, "taker2 after claim");
    assert_untouched(&balance_tree, &t1, &t1_after_s1, "taker1 untouched by swap2 claim");
    assert_untouched(&balance_tree, &f1, &f1_after_s1, "funder1 untouched by swap2 claim");
    assert_untouched(&balance_tree, &f2, &f2_after_s1, "funder2 untouched by swap2 claim");
    assert_eq!(load_sc_asset_value(&c2.data_tree, &c2.scid, &dero_asset()), 0, "SC2 debited");
}

/// Hammer: failed calls (wrong preimage, early refund, attacker refund) must
/// leave EVERY balance byte-identical and the SC still holding the value.
#[test]
fn failed_calls_do_not_move_value() {
    let funder = gen_addr();
    let taker = neg_g_addr();
    let attacker = x_addr(2);
    let init = 50_000u64;
    let mut balance_tree = dero_crypto::graviton::Tree::new("swap-fail-tree");
    let funder_before = register_account(&mut balance_tree, &funder, init);
    let taker_before = register_account(&mut balance_tree, &taker, init);
    let attacker_before = register_account(&mut balance_tree, &attacker, init);

    let preimage = b"fail-safe-preimage-1";
    let hashlock = sha256_hex(preimage);
    let mut ctx = Ctx::new(100); // timeout 10 -> expires at 110
    assert_eq!(
        ctx.call("CreateSwap", vec![
            ("id".into(), ArgValue::Str("f1".into())),
            ("maker".into(), ArgValue::Str(funder.clone())),
            ("taker".into(), ArgValue::Str(taker.clone())),
            ("sellToken".into(), ArgValue::Str("DERO".into())),
            ("sellAmount".into(), ArgValue::U64(1000)),
            ("buyToken".into(), ArgValue::Str("USDT".into())),
            ("buyAmount".into(), ArgValue::U64(500)),
            ("hashlock".into(), ArgValue::Str(hashlock)),
            ("timeout".into(), ArgValue::U64(10)),
        ], 0),
        0,
        "create"
    );
    assert_eq!(
        ctx.call("Fund", vec![
            ("id".into(), ArgValue::Str("f1".into())),
            ("funder".into(), ArgValue::Str(funder.clone())),
        ], 1500),
        0,
        "fund"
    );

    // Wrong preimage claim -> reject, no movement.
    assert_eq!(
        ctx.call("Claim", vec![
            ("id".into(), ArgValue::Str("f1".into())),
            ("preimage".into(), ArgValue::Str("wrong".into())),
        ], 0),
        1,
        "wrong preimage rejects"
    );
    assert!(ctx.transfers().is_empty(), "no payout on wrong preimage");
    assert_untouched(&balance_tree, &funder, &funder_before, "funder after wrong claim");
    assert_untouched(&balance_tree, &taker, &taker_before, "taker after wrong claim");
    assert_eq!(load_sc_asset_value(&ctx.data_tree, &ctx.scid, &dero_asset()), 1500, "SC still holds 1500");

    // Early refund -> reject, no movement.
    assert_eq!(
        ctx.call("Refund", vec![
            ("id".into(), ArgValue::Str("f1".into())),
            ("funder".into(), ArgValue::Str(funder.clone())),
        ], 0),
        1,
        "early refund rejects"
    );
    assert!(ctx.transfers().is_empty(), "no payout on early refund");
    assert_untouched(&balance_tree, &funder, &funder_before, "funder after early refund");
    assert_untouched(&balance_tree, &taker, &taker_before, "taker after early refund");

    // After timeout, attacker refund -> reject, no movement.
    ctx.bl_height = 120;
    assert_eq!(
        ctx.call("Refund", vec![
            ("id".into(), ArgValue::Str("f1".into())),
            ("funder".into(), ArgValue::Str(attacker.clone())),
        ], 0),
        1,
        "attacker refund rejects"
    );
    assert!(ctx.transfers().is_empty(), "no payout to attacker");
    assert_untouched(&balance_tree, &attacker, &attacker_before, "attacker after refund attempt");
    assert_untouched(&balance_tree, &funder, &funder_before, "funder after attacker attempt");
    assert_eq!(load_sc_asset_value(&ctx.data_tree, &ctx.scid, &dero_asset()), 1500, "SC still holds 1500");

    // The real funder can still refund and recovers the value.
    assert_eq!(
        ctx.call("Refund", vec![
            ("id".into(), ArgValue::Str("f1".into())),
            ("funder".into(), ArgValue::Str(funder.clone())),
        ], 0),
        0,
        "funder refund succeeds"
    );
    ctx.settle_external(&mut balance_tree);
    assert_credited(&balance_tree, &funder, &funder_before, 1500, "funder refund");
    assert_untouched(&balance_tree, &taker, &taker_before, "taker after refund");
    assert_untouched(&balance_tree, &attacker, &attacker_before, "attacker after refund");
    assert_eq!(load_sc_asset_value(&ctx.data_tree, &ctx.scid, &dero_asset()), 0, "SC debited");
}

/// Hammer: conservation — the value that leaves the SC's stored balance must
/// land EXACTLY in the recipient's balance-tree entry. No minting, no burn.
#[test]
fn value_is_conserved_sc_debit_equals_recipient_credit() {
    let funder = gen_addr();
    let taker = neg_g_addr();
    let init = 50_000u64;
    let mut balance_tree = dero_crypto::graviton::Tree::new("swap-conserve-tree");
    let funder_before = register_account(&mut balance_tree, &funder, init);
    let taker_before = register_account(&mut balance_tree, &taker, init);

    let preimage = b"conserve-preimage-1";
    let hashlock = sha256_hex(preimage);
    let mut ctx = Ctx::new(100);
    assert_eq!(
        ctx.call("CreateSwap", vec![
            ("id".into(), ArgValue::Str("c1".into())),
            ("maker".into(), ArgValue::Str(funder.clone())),
            ("taker".into(), ArgValue::Str(taker.clone())),
            ("sellToken".into(), ArgValue::Str("DERO".into())),
            ("sellAmount".into(), ArgValue::U64(1000)),
            ("buyToken".into(), ArgValue::Str("USDT".into())),
            ("buyAmount".into(), ArgValue::U64(500)),
            ("hashlock".into(), ArgValue::Str(hashlock)),
            ("timeout".into(), ArgValue::U64(50)),
        ], 0),
        0,
        "create"
    );
    assert_eq!(
        ctx.call("Fund", vec![
            ("id".into(), ArgValue::Str("c1".into())),
            ("funder".into(), ArgValue::Str(funder.clone())),
        ], 1500),
        0,
        "fund"
    );
    let sc_before = load_sc_asset_value(&ctx.data_tree, &ctx.scid, &dero_asset());
    assert_eq!(sc_before, 1500, "SC holds the funded value");

    assert_eq!(
        ctx.call("Claim", vec![
            ("id".into(), ArgValue::Str("c1".into())),
            ("preimage".into(), ArgValue::Str(String::from_utf8(preimage.to_vec()).unwrap())),
        ], 0),
        0,
        "claim"
    );
    ctx.settle_external(&mut balance_tree);

    let sc_after = load_sc_asset_value(&ctx.data_tree, &ctx.scid, &dero_asset());
    let sc_debit = sc_before - sc_after;
    assert_eq!(sc_debit, 1500, "SC debited exactly the funded value");

    // The recipient's balance-tree entry grew by exactly the SC debit.
    assert_credited(&balance_tree, &taker, &taker_before, sc_debit, "taker credit == SC debit");
    // Funder is untouched by the SC external leg (their debit is the ring leg).
    assert_untouched(&balance_tree, &funder, &funder_before, "funder after claim");
}
