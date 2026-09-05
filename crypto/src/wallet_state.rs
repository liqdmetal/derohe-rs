// SPDX-License-Identifier: BSD-3-Clause
//
//! Wallet state layer — clean-room port of the reference wallet's
//! transaction tracking (`walletapi/wallet.go` + the scan loop in
//! `walletapi/daemon_communication.go`).
//!
//! Tracks the wallet's own history by scanning blocks and homomorphically
//! applying each ring member's changes to a running ElGamal balance:
//!   - previous_balance == changed  → anonymous ring member
//!   - previous_balance >  changed  → OUTGOING (sender): amount = prev - new - fees
//!   - previous_balance <  changed  → INCOMING (receiver): amount = new - prev
//! Entries are stored per-SCID, sorted by (topoheight, txpos, pos).
//! Balances are cached per-SCID (mature = spent-capable).

use crate::curve::decode_compressed;
use crate::elgamal::ElGamal;
use crate::transaction::Transaction;
use crate::wallet::decode_balance;
use ark_bn254::Fr;

/// One tracked transfer entry (mirrors Go rpc.Entry).
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub height: u64,
    pub topoheight: u64,
    pub transaction_pos: u64,
    pub pos: u64,
    pub block_hash: String,
    pub txid: String,
    pub timestamp_ms: u64,
    pub fees: u64,
    pub amount: u64,
    pub burn: u64,
    pub incoming: bool,
    pub coinbase: bool,
    pub status: u8, // 0 = receive, 1 = spend
    pub ring_member: bool,
}

/// The wallet's tracked state.
#[derive(Debug, Default)]
pub struct WalletState {
    /// per-SCID entries, sorted by (topoheight, transaction_pos, pos)
    pub entries: std::collections::HashMap<[u8; 32], Vec<Entry>>,
    /// per-SCID cached balances (atomic units)
    pub balances: std::collections::HashMap<[u8; 32], u64>,
    /// last scanned topoheight
    pub scanned_height: u64,
}

impl WalletState {
    pub fn new() -> Self {
        WalletState::default()
    }

    /// Insert an entry, keeping the per-SCID list sorted and replacing any
    /// entry with the same (topoheight, transaction_pos, pos) — the exact
    /// semantics of Go's `InsertReplace` (rescan overwrites).
    pub fn insert_replace(&mut self, scid: [u8; 32], e: Entry) {
        let entries = self.entries.entry(scid).or_default();
        let mut i = entries.len();
        for (idx, existing) in entries.iter().enumerate() {
            if existing.topoheight >= e.topoheight
                && existing.transaction_pos >= e.transaction_pos
                && existing.pos >= e.pos
            {
                i = idx;
                break;
            }
        }
        if i < entries.len()
            && entries[i].topoheight == e.topoheight
            && entries[i].transaction_pos == e.transaction_pos
            && entries[i].pos == e.pos
        {
            // replace: drop this entry and everything after (rescan)
            entries.truncate(i);
        }
        entries.push(e);
        // keep sorted by (topoheight, transaction_pos, pos)
        entries.sort_by(|a, b| {
            (a.topoheight, a.transaction_pos, a.pos).cmp(&(b.topoheight, b.transaction_pos, b.pos))
        });
    }

    /// Filtered transfers (Go `Show_Transfers` semantics).
    pub fn show_transfers(
        &self,
        scid: [u8; 32],
        coinbase: bool,
        incoming: bool,
        outgoing: bool,
        min_height: u64,
        max_height: u64,
    ) -> Vec<&Entry> {
        let max = if max_height == 0 {
            u64::MAX
        } else {
            max_height
        };
        self.entries
            .get(&scid)
            .map(|es| {
                es.iter()
                    .filter(|e| e.height >= min_height && e.height <= max)
                    .filter(|e| {
                        (coinbase && e.coinbase)
                            || (incoming && e.incoming && !e.coinbase)
                            || (outgoing && !(e.incoming || e.coinbase))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Mature (spendable) + locked balance for a SCID.
    /// Locked = coinbase rewards before maturity (we track simply: a
    /// coinbase entry is locked until height + maturity).
    pub fn balance(&self, scid: [u8; 32], current_height: u64) -> (u64, u64) {
        let mature = self.balances.get(&scid).copied().unwrap_or(0);
        // locked: sum of immature coinbase entries (not yet spendable)
        let locked = self
            .entries
            .get(&scid)
            .map(|es| {
                es.iter()
                    .filter(|e| e.coinbase && current_height < e.height + 20)
                    .map(|e| e.amount)
                    .sum()
            })
            .unwrap_or(0);
        (mature, locked)
    }
}

/// Scan one tx where we are a ring member; apply balance changes and
/// classify in/out/ring-member. Returns (scid, entry) if we should record it.
///
/// `prev_bal` / `new_bal` are the wallet's encrypted balance BEFORE and
/// AFTER this tx (from the block scan); `secret` is our account secret.
/// `changes` = ConstructElGamal(C[our_pos], D) applied to prev.
#[allow(clippy::too_many_arguments)]
pub fn process_tx_change(
    secret: &Fr,
    _scid: [u8; 32],
    tx: &Transaction,
    payload_index: usize,
    our_pos: usize,
    prev_bal: &ElGamal,
    block_height: u64,
    topoheight: u64,
    tx_pos: u64,
    block_hash: &str,
    timestamp_ms: u64,
) -> Option<Entry> {
    let p = tx.payloads.get(payload_index)?;
    let st = &p.statement;
    if st.c.len() <= our_pos || st.publickeylist.len() <= our_pos {
        return None;
    }
    let changes = ElGamal::new(st.c[our_pos], st.d);
    let changed_e = prev_bal.add(&changes);
    let prev = decode_balance(prev_bal, secret, 44).unwrap_or(0);
    let changed = decode_balance(&changed_e, secret, 44).unwrap_or(0);

    let fees = st.fees;
    let mut e = Entry {
        height: block_height,
        topoheight,
        transaction_pos: tx_pos,
        pos: payload_index as u64,
        block_hash: block_hash.to_string(),
        txid: hex::encode(tx.get_hash(st.bpp())),
        timestamp_ms,
        fees,
        amount: 0,
        burn: p.burn_value,
        incoming: false,
        coinbase: tx.tx_type == crate::transaction::TX_COINBASE,
        status: 0,
        ring_member: false,
    };

    match prev.cmp(&changed) {
        std::cmp::Ordering::Equal => {
            // ring member — no balance change for us
            e.ring_member = true;
            e.amount = 0;
            e.incoming = false;
            e.status = 0;
        }
        std::cmp::Ordering::Greater => {
            // outgoing (sender): we paid amount + fees
            e.incoming = false;
            e.status = 1;
            e.amount = prev - changed - fees;
            e.ring_member = false;
        }
        std::cmp::Ordering::Less => {
            // incoming (receiver)
            e.incoming = true;
            e.status = 0;
            e.amount = changed - prev;
            e.ring_member = false;
        }
    }
    Some(e)
}

/// Find our position in a payload's statement ring (or None).
pub fn find_our_pos(st: &crate::bulletproof::Statement, our_key: &[u8; 33]) -> Option<usize> {
    st.publickeylist
        .iter()
        .position(|pk| crate::curve::encode_compressed(pk).as_slice() == our_key.as_slice())
}

/// Check whether a tx touches us (we are a ring member in any payload).
pub fn tx_touches_us(tx: &Transaction, our_key: &[u8; 33]) -> bool {
    tx.payloads
        .iter()
        .any(|p| find_our_pos(&p.statement, our_key).is_some())
}

/// Reconstruct a statement's publickeylist from compressed keys
/// (the chain's GetTransaction returns ring addresses; we decode them).
pub fn set_publickeylist_compressed(
    st: &mut crate::bulletproof::Statement,
    ring_keys: &[[u8; 33]],
) {
    st.publickeylist = ring_keys
        .iter()
        .filter_map(|k| decode_compressed(k).ok())
        .collect();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elgamal::ElGamal;
    use crate::hash_to_point::base_g;
    use ark_ec::PrimeGroup;
    use ark_ff::PrimeField;

    fn make_tx(sender_secret: &Fr, ring_keys: &[[u8; 33]], amount: u64) -> Transaction {
        // build a minimal NORMAL tx whose statement has C/D committing the
        // amount at position 0 (sender) and +amount at position 1 (receiver)
        let r = Fr::from(7u64);
        let g = base_g();
        let sender = g.mul_bigint(sender_secret.into_bigint());
        let d = g.mul_bigint(r.into_bigint());
        let mut c = Vec::new();
        for (i, _k) in ring_keys.iter().enumerate() {
            // sender commits -(amount + fees); receiver +amount
            let delta: i64 = match i {
                0 => -((amount + 100) as i64),
                1 => amount as i64,
                _ => 0,
            };
            let abs = delta.unsigned_abs() as u64;
            let mut gd = g.mul_bigint(ark_ff::BigInt::<4>::from(abs));
            if delta < 0 {
                gd = -gd;
            }
            let pk = decode_compressed(&ring_keys[i]).unwrap();
            c.push(gd + pk.mul_bigint(r.into_bigint()));
        }
        let stmt = crate::bulletproof::Statement {
            publickeylist: ring_keys
                .iter()
                .filter_map(|k| decode_compressed(k).ok())
                .collect(),
            c: c.clone(),
            cln: Vec::new(),
            crn: Vec::new(),
            d,
            roothash: [0u8; 32],
            fees: 100,
            pointers: Vec::new(),
        };
        Transaction {
            version: 1,
            source_network: 0,
            dest_network: 0,
            tx_type: crate::transaction::TX_NORMAL,
            value: amount,
            miner_address: [0u8; 33],
            c: [0u8; 32],
            s: [0u8; 32],
            height: 100,
            blid: [0u8; 32],
            scdata: Default::default(),
            payloads: vec![crate::transaction::AssetPayload {
                scid: [0u8; 32],
                burn_value: 0,
                rpc_type: 0,
                rpc_payload: vec![0u8; 145],
                statement: stmt,
                proof: None,
            }],
        }
    }

    #[test]
    fn classify_in_out_ring() {
        // secret for "sender"
        let secret = Fr::from(123u64);
        let g = base_g();
        let sender_pk = g.mul_bigint(secret.into_bigint());
        let sender_comp = crate::curve::encode_compressed(&sender_pk);
        // receiver (position 1) + one decoy
        let recv_secret = Fr::from(999u64);
        let recv_pk = g.mul_bigint(recv_secret.into_bigint());
        let recv_comp = crate::curve::encode_compressed(&recv_pk);
        let d2 = g.mul_bigint(Fr::from(22u64).into_bigint());
        let k2 = crate::curve::encode_compressed(&d2);
        let ring = [sender_comp, recv_comp, k2];

        // sender's balance BEFORE: 1000 (encrypted to the sender key)
        let prev_bal = ElGamal::new(
            g.mul_bigint(Fr::from(1000u64).into_bigint())
                + sender_pk.mul_bigint(Fr::from(5u64).into_bigint()),
            g.mul_bigint(Fr::from(5u64).into_bigint()),
        );
        let tx = make_tx(&secret, &ring, 300);

        // our position = 0 (sender) -> outgoing: prev - (prev - amount - fees)
        let e = process_tx_change(
            &secret, [0u8; 32], &tx, 0, 0, &prev_bal, 100, 100, 0, "blk", 0,
        )
        .unwrap();
        assert!(!e.incoming);
        assert_eq!(e.status, 1);
        assert_eq!(e.amount, 300);
        assert_eq!(e.fees, 100);

        // receiver position = 1 -> incoming: receiver's balance + 300
        let recv_prev = ElGamal::new(
            g.mul_bigint(Fr::from(500u64).into_bigint())
                + recv_pk.mul_bigint(Fr::from(5u64).into_bigint()),
            g.mul_bigint(Fr::from(5u64).into_bigint()),
        );
        let e2 = process_tx_change(
            &recv_secret,
            [0u8; 32],
            &tx,
            0,
            1,
            &recv_prev,
            100,
            100,
            0,
            "blk",
            0,
        )
        .unwrap();
        assert!(e2.incoming);
        assert_eq!(e2.amount, 300);

        // decoy position = 2 -> ring member (decoy's balance encrypted to
        // the decoy's key; decode with the decoy's secret)
        let decoy_secret = Fr::from(22u64);
        let decoy_pk = g.mul_bigint(decoy_secret.into_bigint());
        let decoy_prev = ElGamal::new(
            g.mul_bigint(Fr::from(77u64).into_bigint())
                + decoy_pk.mul_bigint(Fr::from(5u64).into_bigint()),
            g.mul_bigint(Fr::from(5u64).into_bigint()),
        );
        let e3 = process_tx_change(
            &decoy_secret,
            [0u8; 32],
            &tx,
            0,
            2,
            &decoy_prev,
            100,
            100,
            0,
            "blk",
            0,
        )
        .unwrap();
        assert!(e3.ring_member);
        assert_eq!(e3.amount, 0);

        // find_our_pos locates the sender at position 0 by key
        let pos = find_our_pos(&tx.payloads[0].statement, &sender_comp).unwrap();
        assert_eq!(pos, 0);
    }

    #[test]
    fn insert_replace_sorted() {
        let mut ws = WalletState::new();
        let scid = [0u8; 32];
        let mk = |h: u64| Entry {
            height: h,
            topoheight: h,
            transaction_pos: 0,
            pos: 0,
            block_hash: String::new(),
            txid: String::new(),
            timestamp_ms: 0,
            fees: 0,
            amount: h,
            burn: 0,
            incoming: true,
            coinbase: false,
            status: 0,
            ring_member: false,
        };
        ws.insert_replace(scid, mk(3));
        ws.insert_replace(scid, mk(1));
        ws.insert_replace(scid, mk(2));
        let es = ws.entries.get(&scid).unwrap();
        let hs: Vec<u64> = es.iter().map(|e| e.amount).collect();
        assert_eq!(hs, vec![1, 2, 3]);
        // rescan overwrite at the same position: the matched entry and
        // everything after are replaced (Go InsertReplace truncates at the
        // match index, then appends) -> [1, 2]
        ws.insert_replace(scid, mk(2));
        let es = ws.entries.get(&scid).unwrap();
        let hs2: Vec<u64> = es.iter().map(|e| e.amount).collect();
        assert_eq!(hs2, vec![1, 2]);
    }
}
