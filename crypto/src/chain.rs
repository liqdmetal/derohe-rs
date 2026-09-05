// SPDX-License-Identifier: BSD-3-Clause
//
//! Chain state transitions — mirrors derohe `blockchain/transaction_execute.go`.
//!
//! The pure consensus core that applies a block's transactions to the
//! graviton balance trees:
//!   - `calc_block_reward` — block subsidy (Bitcoin-style halving)
//!   - `process_miner_transaction` — coinbase/premine reward distribution
//!   - `process_transaction` — registration / normal / burn / SC balance moves
//!     (homomorphic ElGamal additions, nonce-height updates)
//!
//! Clean-room: written from the reference source, not copied.

use crate::bulletproof::parity;
use crate::curve::decode_compressed;
use crate::elgamal::ElGamal;
use crate::graviton::Tree;
use crate::transaction::{AssetPayload, Transaction, TX_BURN, TX_NORMAL, TX_REGISTRATION, TX_SC};

use ark_bn254::G1Projective;

// config/config.go
pub const BLOCK_TIME: u64 = 18;
pub const BPP_MAINNET: u8 = 3;

// transaction_execute.go
const REWARD_REDUCTION_INTERVAL: u64 = 210000 * 600 / BLOCK_TIME; // 7,000,000
const BASE_REWARD: u64 = (41 * 100000 * BLOCK_TIME) / 600; // 123,000

/// Bitcoin-style block subsidy, halved every interval.
pub fn calc_block_reward(height: u64) -> u64 {
    BASE_REWARD >> ((height + REWARD_REDUCTION_INTERVAL) / REWARD_REDUCTION_INTERVAL)
}

/// tx.Fees(): sum of statement.Fees over SCID-zero payloads.
pub fn tx_fees(tx: &Transaction) -> u64 {
    let mut fees = 0u64;
    for p in &tx.payloads {
        if p.scid.iter().all(|&b| b == 0) {
            fees += p.statement.fees;
        }
    }
    fees
}

/// Go `ConstructElGamal(C[i], D)` — the change ciphertext added
/// homomorphically to a ring member's encrypted balance.
fn construct_elgamal(c: &G1Projective, d: &G1Projective) -> ElGamal {
    ElGamal::new(*c, *d)
}

/// 32-byte big-endian encoding of a u64 (for ElGamal::plus).
pub fn be32(v: u64) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[24..].copy_from_slice(&v.to_be_bytes());
    b
}

/// process_miner_transaction — give the integrator + each miniblock miner
/// their share of (base reward + fees).
pub fn process_miner_transaction(
    miner_address: &[u8; 33],
    premine_value: u64,
    miniblocks: &[crate::block::MiniBlock],
    genesis: bool,
    balance_tree: &mut Tree,
    fees: u64,
    height: u64,
) {
    if genesis {
        // premine: register the miner with the premine value
        let key = decode_compressed(miner_address).expect("miner address must be valid");
        // Go ConstructElGamal(key, base_g): zero ciphertext for this key;
        // Plus(premine) adds premine·G to Left.
        let balance = elgamal_zero(&key).plus(&be32(premine_value));
        let nb = crate::balance_serdes::NonceBalance {
            nonce_height: 0,
            balance,
        };
        balance_tree.put(miner_address, &nb.serialize());
        return;
    }

    // general coinbase: (base + fees) split across miniblocks + integrator
    let base_reward = calc_block_reward(height);
    let full_reward = base_reward + fees;
    let n = miniblocks.len().max(1) as u64;
    let share = full_reward / n;
    let leftover = full_reward - share * n;

    // integrator (miner tx address)
    {
        let balance_serialized = balance_tree
            .get(miner_address)
            .unwrap_or_else(|| panic!("miner address not registered"));
        let mut nb = crate::balance_serdes::NonceBalance::deserialize(&balance_serialized)
            .expect("bad balance");
        nb.balance = nb.balance.plus(&be32(share + leftover));
        balance_tree.put(miner_address, &nb.serialize());
    }

    // other (non-final) miniblocks
    for mbl in miniblocks {
        if mbl.final_block {
            continue;
        }
        let kh16 = &mbl.key_hash[..16];
        let (key_compressed, balance_serialized) = match balance_tree.get_key_value_from_hash(kh16)
        {
            Some(v) => v,
            None => continue, // miner not registered yet — skip (matches Go)
        };
        let mut nb = crate::balance_serdes::NonceBalance::deserialize(&balance_serialized)
            .expect("bad balance");
        nb.balance = nb.balance.plus(&be32(share));
        balance_tree.put(&key_compressed, &nb.serialize());
    }
}

/// ConstructElGamal(pk, base_g): a zero-balance ciphertext for pk.
/// Go: (Left = pk, Right = base_g) is NOT right — read the reference:
/// `ConstructElGamal(key, G)` returns (key·? ). We verified against
/// algebra_elgamal.go: Left = G·(value) + key·r ... with r drawn from the
/// base. For a ZERO balance the reference uses:
///   balance := crypto.ConstructElGamal(acckey.G1(), crypto.ElGamal_BASE_G)
/// which builds (Left = base_g, Right = key) — i.e. value 0, r = sk-derived.
/// Empirically (from the differential): zero ciphertext = (base_g, key).
fn elgamal_zero(key: &G1Projective) -> ElGamal {
    // Go ConstructElGamal(acckey, ElGamal_BASE_G): Left = pk, Right = G.
    ElGamal::new(*key, crate::hash_to_point::base_g())
}

/// process_transaction — apply a tx's balance changes to the state trees.
/// Returns the fees the tx pays. `changed` holds the SC data trees (keyed by
/// SCID); the main balance tree is passed separately. `simulator` enables
/// the testnet/simulator 100M registration bonus (Go: `!IsMainnet() ||
/// chain.simulator`).
pub fn process_transaction(
    changed: &mut std::collections::HashMap<[u8; 32], Tree>,
    tx: &Transaction,
    balance_tree: &mut Tree,
    height: u64,
    simulator: bool,
) -> u64 {
    match tx.tx_type {
        TX_REGISTRATION => {
            // register the address with a zero (or mainnet-early) balance
            let key = decode_compressed(&tx.miner_address).expect("registration address invalid");
            let mut balance = elgamal_zero(&key);
            if simulator {
                balance = balance.plus(&be32(100000000)); // testnet/simulator bonus
            } else if height < 144000 {
                balance = balance.plus(&be32(200)); // early mainnet bonus
            }
            let nb = crate::balance_serdes::NonceBalance {
                nonce_height: 0,
                balance,
            };
            balance_tree.put(&tx.miner_address, &nb.serialize());
            0 // registration pays no fees
        }
        TX_BURN | TX_NORMAL | TX_SC => {
            for payload in &tx.payloads {
                let scid_zero = payload.scid.iter().all(|&b| b == 0);
                let proof_parity = payload.proof.as_ref().map(|p| parity(p)).unwrap_or(false);
                if scid_zero {
                    process_payload(balance_tree, None, payload, proof_parity, height);
                } else {
                    let tree: &mut Tree = changed
                        .get_mut(&payload.scid)
                        .expect("SC tree not in cache");
                    process_payload(tree, Some(balance_tree), payload, proof_parity, height);
                }
            }
            tx_fees(tx)
        }
        _ => panic!("unknown transaction, do not know how to process it"),
    }
}

/// Apply one payload's ring changes (Go process_transaction inner loop).
/// `balance_tree` is the optional fallback for SC trees (immutable here).
fn process_payload(
    tree: &mut Tree,
    balance_tree: Option<&Tree>,
    payload: &AssetPayload,
    parity: bool,
    height: u64,
) {
    let st = &payload.statement;
    let bpp = st.bpp() as usize;
    let ring = st.pointers.len() / bpp;
    for i in 0..ring {
        let key_pointer = &st.pointers[i * bpp..(i + 1) * bpp];
        let (key_compressed, balance_serialized) = match tree.get_key_value_from_hash(key_pointer) {
            Some(kv) => kv,
            None => {
                // SC trees fall back to the main balance tree, init zero
                let kv = balance_tree
                    .expect("balance tree fallback needed")
                    .get_key_value_from_hash(key_pointer)
                    .unwrap_or_else(|| panic!("balance not obtained"));
                let key = decode_compressed(&kv.0).expect("bad key");
                let nb = crate::balance_serdes::NonceBalance {
                    nonce_height: 0,
                    balance: elgamal_zero(&key),
                };
                (kv.0.clone(), nb.serialize())
            }
        };
        let mut nb = match crate::balance_serdes::NonceBalance::deserialize(&balance_serialized) {
            Ok(n) => n,
            Err(_) => {
                // token (SC-asset) trees store 8-byte u64 asset values, not
                // NonceBalances — skip non-conforming leaves (the reference
                // reads SC asset values via LoadSCAssetValue instead)
                continue;
            }
        };
        // homomorphic addition of changes: C[i] (Left), D (Right)
        let echanges = construct_elgamal(&st.c[i], &st.d);
        nb.balance = nb.balance.add(&echanges);
        if (i % 2 == 0) == parity {
            nb.nonce_height = height;
        }
        tree.put(&key_compressed, &nb.serialize());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reward_formula() {
        // mainnet: BaseReward = 41*100000*18/600 = 123000;
        // REWARD_REDUCTION_INTERVAL = 210000*600/18 = 7,000,000.
        // The reference "wipes" the first interval, so at height 0 the shift
        // is (0+7M)/7M = 1 → 123000 >> 1 = 61500.
        assert_eq!(calc_block_reward(0), 61500);
        assert_eq!(calc_block_reward(100), 61500);
        assert_eq!(calc_block_reward(6_999_999), 61500);
        assert_eq!(calc_block_reward(7_000_000), 30750);
        assert_eq!(calc_block_reward(14_000_000), 15375);
    }

    #[test]
    fn contract_uses_signer_detection() {
        use crate::dvm::contract_uses_signer;
        use crate::dvm::parse_smart_contract;
        // SIGNER in body -> true
        let sc = parse_smart_contract(
            "Function F() Uint64\n10 dim x as String\n20 LET x = SIGNER()\n30 RETURN 0\nEnd Function",
        )
        .unwrap();
        assert!(contract_uses_signer(&sc));
        // lowercase signer -> true (case-insensitive dispatch)
        let sc = parse_smart_contract(
            "Function F() Uint64\n10 dim x as String\n20 LET x = signer()\n30 RETURN 0\nEnd Function",
        )
        .unwrap();
        assert!(contract_uses_signer(&sc));
        // no SIGNER -> false
        let sc = parse_smart_contract(
            "Function Init() Uint64\n10 STORE(\"owner\", \"alice\")\n20 RETURN 0\nEnd Function",
        )
        .unwrap();
        assert!(!contract_uses_signer(&sc));
        // REM comment mentioning SIGNER -> false (whole-line comment, Go parity)
        let sc = parse_smart_contract(
            "Function C() Uint64\n10 REM SIGNER is mentioned in a comment\n20 RETURN 0\nEnd Function",
        )
        .unwrap();
        assert!(!contract_uses_signer(&sc));
    }
}

/// process_transaction_sc — SC install/call dispatch (Go
/// blockchain.process_transaction_sc). Handles SC_INSTALL (parse + install +
/// Initialize) and SC_CALL (run entrypoint); commits SC data tree + external
/// transfers on success, or reverts the incoming value on error.
#[allow(clippy::too_many_arguments)]
pub fn process_transaction_sc(
    cache: &mut std::collections::HashMap<[u8; 32], crate::graviton::Tree>,
    ss: &mut crate::sc::Snapshot,
    balance_tree: &mut crate::graviton::Tree,
    sc_meta: &mut crate::graviton::Tree,
    bl_height: u64,
    bl_topoheight: u64,
    bl_timestamp: u64,
    blid: &[u8; 32],
    tx: &Transaction,
    k0_floor_height: Option<u64>,
) -> Result<u64, String> {
    if tx.scdata.is_empty() {
        return Ok(tx_fees(tx));
    }
    let fees = tx_fees(tx);
    // SCACTION must be present
    let action = match tx.scdata.get_uint64("SC_ACTION") {
        Some(a) => a,
        None => return Ok(fees),
    };
    if std::env::var("SC_DEBUG").is_ok() {
        let ks: Vec<String> = tx.scdata.iter().map(|a| a.name.clone()).collect();
        eprintln!("SC tx action={} scdata keys={:?}", action, ks);
    }
    // txid/scid = keccak(core statement). The statement's bpp comes from the
    // WIRE (wallet txs use 2, mainnet 3) — must match Go's GetHash exactly
    // or the SCID (and thus the SC_META key + the state root) diverges.
    let bpp = tx.payloads.first().map(|p| p.statement.bpp()).unwrap_or(3);
    let txid = tx.get_hash(bpp);
    let scid = txid; // install: scid = txid
    let mut call_scid: Option<[u8; 32]> = None; // SC_CALL: the SC_ID
    let incoming_value: std::collections::HashMap<[u8; 32], u64> =
        tx.payloads.iter().map(|p| (p.scid, p.burn_value)).collect();
    // signer: first ring member of the first zero-scid payload
    let signer: [u8; 33] = tx
        .payloads
        .iter()
        .find(|p| p.scid.iter().all(|&b| b == 0))
        .and_then(|p| p.statement.publickeylist.first())
        .map(|pk| {
            let mut s = [0u8; 33];
            s.copy_from_slice(&crate::curve::encode_compressed(pk));
            s
        })
        .unwrap_or([0u8; 33]);

    use crate::sc::{
        execute_sc_function, process_external, read_sc, sanity_check_external_transfers,
        sc_code_key, sc_meta_key, wrapped_tree, TreeWrapper,
    };

    // NOTE: Go wraps the CALLER's sc_tree directly (transaction_execute.go:
    // w_sc_tree := &Tree_Wrapper{Tree: sc_tree, ...}) so meta writes land in
    // the tree the caller hashes. We clone for the wrapper (owning the
    // mutable entry buffer) and flush back into the caller's sc_meta after
    // process_external, so the caller's tree reflects the SC meta (incl. the
    // K0 B2 NoSigner bit) exactly like Go's.
    let mut w_sc_tree = TreeWrapper::new(sc_meta.clone());
    let mut w_sc_data_tree;
    let entrypoint;
    let mut meta_type: u8 = 0;

    match action {
        1 => {
            // SC_INSTALL (Go rpc.SC_INSTALL = 1; SC_CALL = 0)
            let code = match tx.scdata.get_string("SC_CODE") {
                Some(c) => c,
                None => return Err("no code provided".into()),
            };
            if std::env::var("SC_DEBUG").is_ok() {
                eprintln!(
                    "SC code len={} head={:?}",
                    code.len(),
                    &code[..code.len().min(80)]
                );
            }
            if code.is_empty() {
                return Err("no code provided".into());
            }
            let sc =
                crate::dvm::parse_smart_contract(&code).map_err(|e| format!("parse error: {e}"))?;
            if std::env::var("SC_DEBUG").is_ok() {
                let ks: Vec<&String> = sc.functions.keys().collect();
                eprintln!("SC parsed functions: {:?}", ks);
            }
            if sc.functions.contains_key("InitializePrivate") {
                meta_type = 1;
            }
            // K0 Fix B2 (Go mirror): from the fork height onward, a contract
            // that never calls SIGNER() gets the NoSigner bit (0x80) in the
            // meta Type byte — ringsize-2 SC_TX to it is then rejected at
            // consensus. Must match Go byte-for-byte or the SC_META tree
            // (chain state root) diverges. Pre-fork: bit never set.
            if let Some(floor) = k0_floor_height {
                if bl_height >= floor && !crate::dvm::contract_uses_signer(&sc) {
                    meta_type |= 0x80;
                }
            }
            w_sc_data_tree = wrapped_tree(cache, ss, &scid);
            // install: write code + meta into the wrapped trees
            let code_var = crate::dvm::Variable::new_string("", &code);
            w_sc_data_tree.put(&sc_code_key(), &code_var.marshal_binary());
            // the SC's zero-asset balance entry (Go LoadSCAssetValue creates
            // it at the zero-hash asset key: 8 bytes of zero)
            let zerokey = [0u8; 32];
            if w_sc_data_tree.get(&zerokey).is_none() {
                w_sc_data_tree.put(&zerokey, &[0u8; 8]);
            }
            // meta: type byte + zeros (Go SC_META_DATA{MarshalBinary})
            let mut meta_bytes = vec![meta_type];
            meta_bytes.extend_from_slice(&[0u8; 32]); // datahash zero (pre-HF2)
            w_sc_tree.put(&sc_meta_key(&scid), &meta_bytes);
            // entrypoint: PRIVATE bit (0x01) is tested BITWISE like Go's
            // meta.IsPrivate() — the K0 NoSigner bit (0x80) may also be set,
            // making meta_type 0x81. `== 1` would wrongly select Initialize.
            entrypoint = if meta_type & 0x01 == 0x01 {
                "InitializePrivate"
            } else {
                "Initialize"
            }
            .to_string();
            let (balance, sc_parsed) = read_sc(&mut w_sc_data_tree, &scid);
            let sc_parsed = sc_parsed.ok_or("SC not found")?;
            execute_sc_function(
                &mut w_sc_tree,
                &mut w_sc_data_tree,
                &scid,
                bl_height,
                bl_topoheight,
                bl_timestamp,
                blid,
                &txid,
                &sc_parsed,
                &entrypoint,
                balance,
                &signer,
                &incoming_value,
                &[],
                fees,
            )?;
        }
        0 => {
            // SC_CALL (Go rpc.SC_CALL = 0)
            let scid = tx.scdata.get_hash("SC_ID").unwrap_or([0u8; 32]);
            // the SC_ID is the data-tree key for the call (the outer `scid`
            // is the txid for installs) — capture it for the cache flush
            call_scid = Some(scid);
            let entry = tx
                .scdata
                .get_string("entrypoint")
                .ok_or("no entrypoint provided")?;
            entrypoint = entry;
            // must be installed
            if w_sc_tree.get(&sc_meta_key(&scid)).is_none() {
                return Err("scid not installed".into());
            }
            w_sc_data_tree = wrapped_tree(cache, ss, &scid);
            let (balance, sc_parsed) = read_sc(&mut w_sc_data_tree, &scid);
            let sc_parsed = sc_parsed.ok_or("SC not found")?;
            // pass the tx's SCDATA (marshalled) so the entrypoint receives
            // its parameters (e.g. SetVal(x Uint64) gets x from here)
            let scdata_bytes = tx.scdata.marshal_binary().unwrap_or_default();
            execute_sc_function(
                &mut w_sc_tree,
                &mut w_sc_data_tree,
                &scid,
                bl_height,
                bl_topoheight,
                bl_timestamp,
                blid,
                &txid,
                &sc_parsed,
                &entrypoint,
                balance,
                &signer,
                &incoming_value,
                &scdata_bytes,
                fees,
            )?;
        }
        _ => return Err("unknown action".into()),
    }

    // sanity check + commit
    sanity_check_external_transfers(&mut w_sc_data_tree, balance_tree, &scid)?;
    process_external(
        cache,
        ss,
        balance_tree,
        &scid,
        &mut w_sc_data_tree,
        &mut w_sc_tree,
    );
    // CRITICAL: w_sc_data_tree wraps a CLONE of the cache's tree — its
    // STORE writes must be flushed BACK into the cache so the caller sees
    // the final SC data (the Go wrapper mutates the cache's tree in place).
    // Keyed by the SC's id (the SC_ID for calls, the txid for installs).
    let flush_scid = call_scid.unwrap_or(scid);
    cache.insert(flush_scid, w_sc_data_tree.tree.clone());
    // flush the cloned meta tree's SC-meta entry back into the caller's
    // sc_meta so the caller's tree reflects the SC meta (incl. the K0 B2
    // NoSigner bit), matching Go where the wrapper wraps the caller's tree
    // directly.
    let meta_key = sc_meta_key(&scid);
    if let Some(mut v) = w_sc_tree.get(&meta_key) {
        // Go sets meta.DataHash = the SCID data tree's hash in the commit
        // phase (blockchain.go:983/991: meta.DataHash = v.Hash()). Without
        // it the SC_META entry bytes diverge from the chain's.
        if let Some(data_tree) = cache.get(&scid) {
            let dh = data_tree.hash();
            if v.len() == 33 {
                v[1..].copy_from_slice(&dh);
            }
        }
        sc_meta.put(&meta_key, &v);
    }
    Ok(fees)
}

/// Add_Complete_Block — apply a full block (its txs + the miner tx) to the
/// persistent balance + SC_META trees. Returns (fees, balance_root,
/// sc_meta_root, per-SCID SC data trees). Mirrors blockchain.go
/// Add_Complete_Block's execute phase (the commit/snapshot part is the
/// caller's store).
pub fn add_complete_block(
    balance_tree: &mut Tree,
    sc_meta: &mut Tree,
    bl: &crate::block::Block,
    txs: &[Transaction],
    height: u64,
    genesis: bool,
    k0_floor: Option<u64>,
    // accumulated SC data trees from prior blocks — the snapshot source so
    // SC calls can see contracts installed in earlier blocks
    prior_sc_data: &std::collections::HashMap<[u8; 32], Tree>,
) -> Result<
    (
        u64,
        [u8; 32],
        [u8; 32],
        std::collections::HashMap<[u8; 32], Tree>,
    ),
    String,
> {
    // ensure the miner is registered (zero balance) so the reward add works
    if !genesis
        && balance_tree
            .get(&bl.miner_tx.miner_address.to_vec())
            .is_none()
    {
        if let Ok(pk) = decode_compressed(&bl.miner_tx.miner_address) {
            let zb = ElGamal::new(pk, crate::hash_to_point::base_g());
            let nb = crate::balance_serdes::NonceBalance {
                nonce_height: 0,
                balance: zb,
            };
            balance_tree.put(&bl.miner_tx.miner_address, &nb.serialize());
        }
    }
    let mut fees = 0u64;
    let mut sc_data: std::collections::HashMap<[u8; 32], Tree> = prior_sc_data.clone();
    // the snapshot must contain the PRIOR blocks' SC data trees so SC calls
    // can read variables installed earlier
    let mut ss = crate::sc::Snapshot {
        trees: std::collections::HashMap::new(),
    };
    for (scid, tree) in &sc_data {
        ss.trees
            .insert(String::from_utf8_lossy(scid).to_string(), tree.clone());
    }
    for tx in txs {
        // the changed-cache must contain the prior SC data trees so token
        // (non-zero-scid) payloads resolve their balance tree
        let mut changed = std::collections::HashMap::new();
        for (scid, tree) in &sc_data {
            changed.insert(*scid, tree.clone());
        }
        fees += process_transaction(&mut changed, tx, balance_tree, height, true);
        if tx.tx_type == TX_SC {
            let mut cache = std::collections::HashMap::new();
            let blid = bl.get_hash();
            let _ = process_transaction_sc(
                &mut cache,
                &mut ss,
                balance_tree,
                sc_meta,
                height,
                height,
                0,
                &blid,
                tx,
                k0_floor,
            )
            .map_err(|e| eprintln!("SC apply error: {e}"));
            // capture the SC data trees (per-SCID: code + variables) so the
            // node can serve DERO.GetSC
            for (scid, tree) in cache {
                if std::env::var("SC_DEBUG").is_ok() {
                    eprintln!(
                        "block: SC cache[{:?}] {} keys",
                        &scid[..4],
                        crate::graviton::tree_keys(&tree).len()
                    );
                }
                sc_data.insert(scid, tree);
            }
        }
    }
    process_miner_transaction(
        &bl.miner_tx.miner_address,
        bl.miner_tx.value,
        &bl.mini_blocks,
        genesis,
        balance_tree,
        fees,
        height,
    );
    Ok((fees, balance_tree.hash(), sc_meta.hash(), sc_data))
}
