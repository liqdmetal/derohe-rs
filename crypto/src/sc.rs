//! SC execution plumbing — mirrors derohe `dvm/sc.go` + `dvm/simulator.go`.
//!
//! Wraps graviton trees so SC writes can be discarded on error, runs the DVM
//! entrypoint, then commits data/transfers or reverts.

use crate::dvm::{self, run_smart_contract_internal, SmartContract, Variable};
use crate::elgamal::ElGamal;
use crate::graviton::Tree;
use crate::hash_to_point::base_g;
use crate::curve::decode_compressed;

/// Tree_Wrapper (sc.go): pending writes + external transfers over a tree.
pub struct TreeWrapper {
    pub tree: Tree,
    pub entries: std::collections::HashMap<Vec<u8>, Vec<u8>>,
    pub transfers: Vec<TransferExternal>,
}

#[derive(Clone)]
pub struct TransferExternal {
    pub asset: [u8; 32],
    pub address: [u8; 33],
    pub amount: u64,
}

impl TreeWrapper {
    pub fn new(tree: Tree) -> Self {
        Self { tree, entries: std::collections::HashMap::new(), transfers: Vec::new() }
    }
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        if let Some(v) = self.entries.get(key) {
            return Some(v.clone());
        }
        self.tree.get(key)
    }
    pub fn put(&mut self, key: &[u8], value: &[u8]) {
        self.entries.insert(key.to_vec(), value.to_vec());
    }
    pub fn delete(&mut self, key: &[u8]) {
        self.entries.insert(key.to_vec(), Vec::new());
    }
}

/// SC_Meta_Key / SC_Code_Key (sc.go).
pub fn sc_meta_key(scid: &[u8; 32]) -> Vec<u8> {
    scid.to_vec()
}
pub fn sc_code_key() -> Vec<u8> {
    // Variable{Type: String, ValueString: "C"}.MarshalBinaryPanic()
    let v = Variable::new_string("", "C");
    v.marshal_binary()
}

/// LoadSCAssetValue: the SC's balance for an asset (8-byte BE u64 at asset key).
pub fn load_sc_asset_value(data: &TreeWrapper, scid: &[u8; 32], asset: &[u8; 32]) -> u64 {
    let key = asset.to_vec();
    match data.get(&key) {
        Some(v) if v.len() == 8 => u64::from_be_bytes(v.try_into().unwrap()),
        _ => 0,
    }
}

/// StoreSCValue: 8-byte BE u64 at `key` in the SC data tree.
pub fn store_sc_value(data: &mut TreeWrapper, _scid: &[u8; 32], key: &[u8], value: &[u8]) {
    data.put(key, value);
}

/// Wrapped_tree (sc.go): grab the SC data tree (from cache or snapshot),
/// wrapping it so writes are discardable.
pub fn wrapped_tree(cache: &mut std::collections::HashMap<[u8; 32], Tree>, ss: &Snapshot, id: &[u8; 32]) -> TreeWrapper {
    let tree = if let Some(t) = cache.get(id) {
        t.clone()
    } else {
        ss.get_tree(&String::from_utf8_lossy(id).to_string())
    };
    cache.insert(*id, tree.clone());
    TreeWrapper::new(tree)
}

/// Minimal snapshot: a set of named trees (the oracle provides them).
pub struct Snapshot {
    pub trees: std::collections::HashMap<String, Tree>,
}
impl Snapshot {
    pub fn get_tree(&self, name: &str) -> Tree {
        self.trees.get(name).cloned().unwrap_or_else(|| Tree::new(name))
    }
}

/// Execute_sc_function (sc.go): run the entrypoint with the DVM, commit the
/// SC data tree writes + external transfers on success, else return err.
#[allow(clippy::too_many_arguments)]
pub fn execute_sc_function(
    w_sc_tree: &mut TreeWrapper,
    data_tree: &mut TreeWrapper,
    scid: &[u8; 32],
    bl_height: u64,
    bl_topoheight: u64,
    bl_timestamp: u64,
    blid: &[u8; 32],
    txid: &[u8; 32],
    sc_parsed: &SmartContract,
    entrypoint: &str,
    balance_at_start: u64,
    signer: &[u8; 33],
    incoming_value: &std::collections::HashMap<[u8; 32], u64>,
    scdata_bytes: &[u8],
    gasstorage_incoming: u64,
) -> Result<(u64, u64), String> {
    // incoming asset credits
    for (asset, value) in incoming_value {
        let stored = load_sc_asset_value(data_tree, scid, asset);
        let newv = stored.wrapping_add(*value);
        store_sc_value(data_tree, scid, asset, &newv.to_be_bytes());
    }

    let params: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    let mut state = dvm::SharedState::new(scid, blid, txid, signer, bl_height, bl_topoheight, bl_timestamp);
    let result = run_smart_contract_internal(sc_parsed, entrypoint, &mut state, &params)?;

    // confirm: result must be Uint64 0
    if result.vtype != dvm::Vtype::Uint64 || result.value_uint64 != 0 {
        return Err("Discarded knowingly".into());
    }

    // flush the DVM's STORE writes (TXStorage.raw_keys) into the data tree.
    // Go: the interpreter's StoreSCValue writes go through the same wrapper,
    // so every STORE lands in the SC data tree (key = DataKey marshal with
    // the trailing type byte, value = Variable marshal).
    for (k, v) in state.store.raw_keys.iter() {
        let kb = k.as_bytes();
        if v.is_empty() {
            data_tree.tree.delete(kb);
        } else {
            data_tree.tree.put(kb, v);
        }
    }

    // commit the wrapped data tree entries
    for (k, v) in data_tree.entries.iter() {
        if v.is_empty() {
            data_tree.tree.delete(k);
        } else {
            data_tree.tree.put(k, v);
        }
    }
    data_tree.entries.clear();

    let _ = (w_sc_tree, balance_at_start, scdata_bytes, gasstorage_incoming);
    Ok((0, 0))
}

/// ReadSC (sc.go): the SC's DERO balance + parsed code.
pub fn read_sc(data_tree: &mut TreeWrapper, scid: &[u8; 32]) -> (u64, Option<SmartContract>) {
    let zerohash = [0u8; 32];
    let balance = load_sc_asset_value(data_tree, scid, &zerohash);
    let code_key = sc_code_key();
    let sc = match data_tree.get(&code_key) {
        Some(bytes) => {
            // Variable{String}.UnmarshalBinary -> the code
            match Variable::unmarshal_binary(&bytes) {
                Ok(var) if var.vtype == dvm::Vtype::String => dvm::parse_smart_contract(&var.value_string).ok(),
                _ => None,
            }
        }
        None => None,
    };
    (balance, sc)
}

/// SanityCheckExternalTransfers (simulator.go): total per-asset transfers
/// must not exceed the SC's stored balance (except its own token).
pub fn sanity_check_external_transfers(
    w_sc_data_tree: &mut TreeWrapper,
    balance_tree: &Tree,
    scid: &[u8; 32],
) -> Result<(), String> {
    let mut total_per_asset: std::collections::HashMap<[u8; 32], u64> = std::collections::HashMap::new();
    for transfer in &w_sc_data_tree.transfers {
        if transfer.amount == 0 {
            continue;
        }
        if transfer.asset != *scid {
            let cur = total_per_asset.get(&transfer.asset).copied().unwrap_or(0);
            if cur.wrapping_add(transfer.amount) <= cur {
                return Err("Balance calculation overflow".into());
            }
            total_per_asset.insert(transfer.asset, cur + transfer.amount);
        }
    }
    for (asset, value) in total_per_asset {
        let stored = load_sc_asset_value(w_sc_data_tree, scid, &asset);
        if asset != *scid && stored.wrapping_sub(value) > stored {
            return Err("Balance calculation underflow".into());
        }
        store_sc_value(w_sc_data_tree, scid, &asset, &(stored - value).to_be_bytes());
    }
    // all destinations must be registered
    for transfer in &w_sc_data_tree.transfers {
        if balance_tree.get(&transfer.address.to_vec()).is_none() {
            return Err("account is unregistered".into());
        }
    }
    Ok(())
}

/// ErrorRevert (simulator.go): on SC error, give the incoming value back to
/// the signer (per asset, from the right tree).
pub fn error_revert(
    cache: &mut std::collections::HashMap<[u8; 32], Tree>,
    ss: &Snapshot,
    balance_tree: &mut Tree,
    signer: &[u8; 33],
    scid: &[u8; 32],
    incoming_values: &std::collections::HashMap<[u8; 32], u64>,
) {
    let zeroscid = [0u8; 32];
    for (scid_asset, burnvalue) in incoming_values {
        let curbtree: &mut Tree = if *scid_asset == zeroscid {
            balance_tree
        } else if *scid_asset == *scid {
            cache.entry(*scid).or_insert_with(|| ss.get_tree(&String::from_utf8_lossy(scid).to_string()))
        } else {
            cache.entry(*scid_asset).or_insert_with(|| ss.get_tree(&String::from_utf8_lossy(scid_asset).to_string()))
        };
        let balance_serialized = curbtree
            .get(signer)
            .unwrap_or_else(|| panic!("signer balance missing"));
        let mut nb = crate::balance_serdes::NonceBalance::deserialize(&balance_serialized)
            .expect("bad balance");
        nb.balance = nb.balance.plus(&crate::chain::be32(*burnvalue));
        curbtree.put(signer, &nb.serialize());
    }
}

/// ProcessExternal (simulator.go): commit the SC data tree writes + meta,
/// then execute each external transfer (add the amount to the recipient's
/// balance in the right tree).
pub fn process_external(
    cache: &mut std::collections::HashMap<[u8; 32], Tree>,
    ss: &Snapshot,
    balance_tree: &mut Tree,
    scid: &[u8; 32],
    w_sc_data_tree: &mut TreeWrapper,
    w_sc_tree: &mut TreeWrapper,
) {
    cache.insert(*scid, w_sc_data_tree.tree.clone());

    for (k, v) in w_sc_data_tree.entries.iter() {
        if v.is_empty() {
            w_sc_data_tree.tree.delete(k);
        } else {
            w_sc_data_tree.tree.put(k, v);
        }
    }
    w_sc_data_tree.entries.clear();
    for (k, v) in w_sc_tree.entries.iter() {
        w_sc_tree.tree.put(k, v);
    }
    w_sc_tree.entries.clear();

    let zeroscid = [0u8; 32];
    // first verify all destinations are registered (immutable pass)
    for transfer in w_sc_data_tree.transfers.iter() {
        if transfer.amount == 0 {
            continue;
        }
        if balance_tree.get(&transfer.address.to_vec()).is_none() {
            panic!("sending to non registered account");
        }
    }
    for transfer in w_sc_data_tree.transfers.iter() {
        if transfer.amount == 0 {
            continue;
        }
        let curbtree: &mut Tree = if transfer.asset == zeroscid {
            balance_tree
        } else if transfer.asset == *scid {
            cache.get_mut(scid).expect("sc tree in cache")
        } else {
            cache.entry(transfer.asset).or_insert_with(|| ss.get_tree(&String::from_utf8_lossy(&transfer.asset).to_string()))
        };
        let addr_bytes = transfer.address.to_vec();
        let balance_serialized = match curbtree.get(&addr_bytes) {
            Some(b) => b,
            None => {
                // init zero balance from the address key
                let pk = decode_compressed(&addr_bytes).expect("bad key");
                let nb = crate::balance_serdes::NonceBalance {
                    nonce_height: 0,
                    balance: ElGamal::new(pk, base_g()),
                };
                nb.serialize()
            }
        };
        let mut nb = crate::balance_serdes::NonceBalance::deserialize(&balance_serialized)
            .expect("bad balance");
        nb.balance = nb.balance.plus(&crate::chain::be32(transfer.amount));
        curbtree.put(&addr_bytes, &nb.serialize());
    }
    w_sc_data_tree.transfers.clear();
}
