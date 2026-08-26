//! Rust wallet: derive keys from recovery words, build a real NORMAL
//! transfer, and broadcast it to the daemon. End-to-end proof that the
//! Rust implementation can spend on a live DERO network.

use dero_crypto::bulletproof::{generate_proof, verify, Statement, Witness};
use dero_crypto::curve::encode_compressed;
use dero_crypto::elgamal::ElGamal;
use dero_crypto::hash_to_point::base_g;
use dero_crypto::mnemonics::words_to_key;
use dero_crypto::rpc_addr::address_to_compressed;
use dero_crypto::tx_builder::{build_transaction, RingMember, Transfer};
use dero_crypto::wallet::{calc_r, generate_shared_secret, reduced_hash};
use ark_bn254::Fr;
use ark_ec::PrimeGroup;
use ark_ff::PrimeField;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 5 {
        eprintln!("usage: wallet.exe <words> <dest> <amount> <daemon>");
        std::process::exit(1);
    }
    let words = &args[1];
    let dest = &args[2];
    let amount: u64 = args[3].parse().expect("amount");
    let daemon = &args[4];

    // 1. derive the wallet keys
    let seed = words_to_key(&words.split_whitespace().map(|w| w.to_string()).collect::<Vec<_>>())
        .expect("words_to_key");
    let mut le = [0u8; 32];
    for i in 0..32 {
        le[i] = seed[31 - i];
    }
    let secret = Fr::from_le_bytes_mod_order(&le);
    let sender = base_g().mul_bigint(secret.into_bigint());
    let sender_comp = encode_compressed(&sender);
    println!("sender:   {}", hex::encode(&sender_comp[..16]));

    // 2. fetch a ring from the daemon (GetRandomAddress)
    let ring_addrs: Vec<String> = json_rpc(daemon, "DERO.GetRandomAddress", serde_json::json!({}))
        .get("result")
        .and_then(|r| r.get("address"))
        .and_then(|a| a.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    if ring_addrs.len() < 8 {
        eprintln!("need >= 8 ring members, got {}", ring_addrs.len());
        std::process::exit(1);
    }
    // find the wallet's OWN address: the registered address whose compressed
    // key matches the derived sender key
    let regs: Vec<String> = json_rpc(daemon, "DERO.GetRegistrations", serde_json::json!({}))
        .get("result")
        .and_then(|r| r.get("addresses"))
        .and_then(|a| a.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let sender_hex = hex::encode(sender_comp);
    let mut self_addr = ring_addrs[0].clone();
    for reg in &regs {
        if reg.trim_start_matches("0x") == sender_hex {
            // it's a compressed key; find its bech32 in ring_addrs
            if let Some(a) = ring_addrs.iter().find(|a| {
                address_to_compressed(a).map(|c| hex::encode(c) == sender_hex).unwrap_or(false)
            }) {
                self_addr = a.clone();
                break;
            }
        }
    }
    println!("self addr: {}", self_addr.chars().take(24).collect::<String>());
    // ring = [self, dest, others] — ALL DISTINCT by compressed key
    let mut ring_members: Vec<String> = vec![self_addr.clone(), dest.to_string()];
    for a in ring_addrs.into_iter().filter(|a| a != &self_addr && a.as_str() != dest) {
        // skip if the key is already present (dup)
        let ak = address_to_compressed(&a).unwrap_or_default();
        let dup = ring_members.iter().any(|m| {
            m == &a || address_to_compressed(m).map(|c| c == ak).unwrap_or(false)
        });
        if !dup {
            ring_members.push(a);
        }
        if ring_members.len() == 8 {
            break;
        }
    }
    if ring_members.len() < 8 {
        eprintln!("need 8 distinct ring members, got {}", ring_members.len());
        std::process::exit(1);
    }

    // 3. fetch encrypted balances + roothash from the daemon
    //    (at the resolved topoheight, matching the roothash snapshot)
    let eb0 = json_rpc(
        daemon,
        "DERO.GetEncryptedBalance",
        serde_json::json!({"address": ring_members[0], "scid": "0".repeat(64), "topoheight": -1}),
    );
    let topoheight = eb0
        .get("result")
        .and_then(|r| r.get("topoheight"))
        .and_then(|t| t.as_i64())
        .unwrap_or(-1);
    println!("resolved topoheight: {}", topoheight);
    let mut ring: Vec<RingMember> = Vec::new();
    let mut roothash = [0u8; 32];
    for (i, addr) in ring_members.iter().enumerate() {
        let eb = json_rpc(
            daemon,
            "DERO.GetEncryptedBalance",
            serde_json::json!({"address": addr, "scid": "0".repeat(64), "topoheight": topoheight}),
        );
        let res = eb.get("result").expect("balance result");
        let treehash = res.get("treehash").and_then(|t| t.as_str()).unwrap_or("");
        if treehash.len() == 64 {
            let mut rh = [0u8; 32];
            rh.copy_from_slice(&hex::decode(treehash).expect("roothash hex"));
            if i == 0 {
                roothash = rh;
            }
        }
        let data = res.get("data").and_then(|d| d.as_str()).unwrap_or("");
        let raw = hex::decode(data).unwrap_or_default();
        // NonceBalance = uvarint nonce + 66-byte ElGamal; unregistered
        // members get a zero balance (Go constructs (G, G) for them)
        let balance = if raw.len() >= 67 {
            let mut pos = 0;
            while pos < raw.len() && raw[pos] & 0x80 != 0 {
                pos += 1;
            }
            pos += 1;
            ElGamal::deserialize(&raw[pos..pos + 66]).expect("elgamal")
        } else {
            // zero balance: Left = G, Right = G (Go's ConstructElGamal)
            let g = base_g();
            ElGamal {
                left: g,
                right: g,
            }
        };
        let comp = address_to_compressed(addr).expect("addr");
        let mut pk = [0u8; 33];
        pk.copy_from_slice(&comp);
        if i == 0 {
            // debug: decode the self balance
            let val = dero_crypto::tx_builder::decode_balance(&balance, &secret).unwrap_or(u64::MAX);
            println!("self decoded balance: {}", val);
        }
        ring.push(RingMember {
            public_key: pk,
            balance,
            balance_decoded: 0,
        });
    }

    // the sender's DECRYPTED balance (via the daemon's wallet lookup) —
    // needed for the witness; set it on the self member (index 0)
    let bal_resp = json_rpc(daemon, "DERO.GetBalance", serde_json::json!({"address": self_addr}));
    let self_balance = bal_resp
        .get("result")
        .and_then(|r| r.get("balance"))
        .and_then(|b| b.as_u64())
        .unwrap_or(0);
    ring[0].balance_decoded = self_balance;
    println!("self decrypted balance: {}", self_balance);
    // debug: print each ring member's pointer (graviton hash truncated to bpp)
    for (i, m) in ring.iter().enumerate() {
        let ptr = &dero_crypto::graviton::grav_hash(&m.public_key)[..2];
        println!("  member[{}] {} ptr={}", i, hex::encode(&m.public_key[..6]), hex::encode(ptr));
    }

    // 4. build the transaction — reference the CURRENT block hash + height
    //    (the daemon's GetInfo provides them; the tx must reference a real
    //    block or the chain rejects it)
    let info = json_rpc(daemon, "DERO.GetInfo", serde_json::json!({}));
    let height: u64 = info
        .get("result")
        .and_then(|r| r.get("height"))
        .and_then(|h| h.as_u64())
        .unwrap_or(0);
    let mut blid = [0u8; 32];
    // the tip block hash (the tx must reference a real block)
    let blid_hex = info
        .get("result")
        .and_then(|r| r.get("top_block_hash"))
        .and_then(|b| b.as_str())
        .unwrap_or("");
    if blid_hex.len() == 64 {
        blid.copy_from_slice(&hex::decode(blid_hex).expect("blid hex"));
    }
    println!("height: {} blid: {}", height, hex::encode(blid)[..16].to_string());
    let transfers = vec![Transfer {
        destination: dest.clone(),
        amount,
        burn: 0,
        scid: [0u8; 32],
        payload_rpc: Vec::new(),
    }];
    let tx = build_transaction(
        &transfers,
        &[ring],
        0,
        1,
        &blid,
        height,
        &dero_crypto::rpc_args::Arguments::default(),
        &roothash,
        9,
        0,
        &secret,
        &[0x5au8; 16384],
    )
    .expect("build_transaction");

    // 5. self-verify the proof
    let txid = tx.get_hash(2);
    println!("txid: {}", hex::encode(txid));
    for (i, p) in tx.payloads.iter().enumerate() {
        let ok = verify(&p.scid, i as i32, &p.statement, p.proof.as_ref().unwrap(), &txid, p.burn_value);
        println!("proof[{}] self-verify: {}", i, ok);
        if !ok {
            // debug: does the proof bind a different txid? recompute with bpp=3
            let txid3 = tx.get_hash(3);
            let ok3 = verify(&p.scid, i as i32, &p.statement, p.proof.as_ref().unwrap(), &txid3, p.burn_value);
            println!("  (bpp3 txid verify: {})", ok3);
        }
    }

    // 6. broadcast (simnode's SubmitTX expects {"blob": "hex"})
    let blob = hex::encode(tx.serialize(2));
    // cross-check: what txid does GO compute for this blob?
    let chk = json_rpc(daemon, "DERO.CheckTxHash", serde_json::json!({"blob": blob}));
    let go_txid = chk.get("result").and_then(|r| r.get("txid")).and_then(|t| t.as_str()).unwrap_or("ERR").to_string();
    println!("GO txid for our blob: {}", go_txid.chars().take(24).collect::<String>());
    println!("our txid:            {}", hex::encode(txid).chars().take(24).collect::<String>());
    let resp = json_rpc(daemon, "DERO.SubmitTX", serde_json::json!({"blob": blob}));
    println!("submit: {}", serde_json::to_string(&resp).unwrap_or_default().chars().take(200).collect::<String>());
}

fn sender_bech32(comp: &[u8; 33]) -> String {
    // minimal bech32 for the wallet address (testnet deto1 prefix)
    let mut data = vec![0u8; 0];
    data.extend_from_slice(comp);
    let mut conv = vec![0u8; 0];
    // 8-to-5 bit conversion
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for b in comp.iter().chain(std::iter::once(&0u8)) {
        acc = (acc << 8) | *b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            conv.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        conv.push(((acc << (5 - bits)) & 31) as u8);
    }
    let charset = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let mut s = String::from("deto1");
    for c in conv {
        s.push(charset[c as usize] as char);
    }
    s
}

fn json_rpc(daemon: &str, method: &str, params: serde_json::Value) -> serde_json::Value {
    let body = serde_json::json!({"jsonrpc": "2.0", "id": 0, "method": method, "params": params});
    let body_str = body.to_string();
    use std::io::{Read, Write};
    let mut client = std::net::TcpStream::connect(daemon).expect("connect");
    client
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .ok();
    let req = format!(
        "POST /json_rpc HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        daemon,
        body_str.len(),
        body_str
    );
    client.write_all(req.as_bytes()).expect("write");
    // read the response headers
    let mut buf = [0u8; 8192];
    let mut header = Vec::new();
    loop {
        let n = client.read(&mut buf).expect("read hdr");
        if n == 0 {
            break;
        }
        header.extend_from_slice(&buf[..n]);
        if header.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let head = String::from_utf8_lossy(&header).to_string();
    let mut body_resp = String::new();
    if let Some(idx) = head.find("\r\n\r\n") {
        let mut rest = header[idx + 4..].to_vec();
        // Content-Length
        let cl = head
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("content-length"))
            .and_then(|l| l.split(':').nth(1))
            .and_then(|v| v.trim().parse::<usize>().ok());
        match cl {
            Some(len) => {
                while rest.len() < len {
                    let n = client.read(&mut buf).expect("read body");
                    if n == 0 {
                        break;
                    }
                    rest.extend_from_slice(&buf[..n]);
                }
                rest.truncate(len);
                body_resp = String::from_utf8_lossy(&rest).to_string();
            }
            None => {
                // chunked
                let mut acc = String::from_utf8_lossy(&rest).to_string();
                let mut tmp = Vec::new();
                loop {
                    let n = client.read(&mut buf).expect("read chunk");
                    if n == 0 {
                        break;
                    }
                    tmp.extend_from_slice(&buf[..n]);
                    let s = String::from_utf8_lossy(&tmp).to_string();
                    if let Some(crlf) = s.find("\r\n") {
                        let size = usize::from_str_radix(s[..crlf].trim(), 16).unwrap_or(0);
                        if size == 0 {
                            break;
                        }
                        acc.push_str(&s[crlf + 2..crlf + 2 + size]);
                        tmp.clear();
                    }
                }
                body_resp = acc;
            }
        }
    }
    serde_json::from_str(&body_resp).unwrap_or(serde_json::json!({"error": body_resp}))
}
