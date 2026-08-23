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
fn be32(v: u64) -> [u8; 32] {
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
        let nb = crate::balance_serdes::NonceBalance { nonce_height: 0, balance };
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
        let (key_compressed, balance_serialized) = balance_tree
            .get_key_value_from_hash(kh16)
            .unwrap_or_else(|| panic!("miniblock miner not found"));
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
/// SCID); the main balance tree is passed separately.
pub fn process_transaction(
    changed: &mut std::collections::HashMap<[u8; 32], Tree>,
    tx: &Transaction,
    balance_tree: &mut Tree,
    height: u64,
) -> u64 {
    match tx.tx_type {
        TX_REGISTRATION => {
            // register the address with a zero (or mainnet-early) balance
            let key = decode_compressed(&tx.miner_address).expect("registration address invalid");
            let mut balance = elgamal_zero(&key);
            if height < 144000 {
                balance = balance.plus(&be32(200)); // early mainnet bonus
            }
            let nb = crate::balance_serdes::NonceBalance { nonce_height: 0, balance };
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
                    let tree: &mut Tree = changed.get_mut(&payload.scid).expect("SC tree not in cache");
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
    let bpp = BPP_MAINNET as usize;
    let st = &payload.statement;
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
        let mut nb = crate::balance_serdes::NonceBalance::deserialize(&balance_serialized)
            .expect("bad balance");
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
}
