use dero_crypto::block::Block;

fn main() {
    let blob =
        std::fs::read_to_string(r"C:\Users\$USER\AppData\Local\Temp\mainnet_blk.txt").unwrap();
    let raw = hex::decode(blob.trim()).unwrap();
    let blk = Block::deserialize(&raw).unwrap();
    let mt = &blk.miner_tx;
    println!("miner tx_type: {}", mt.tx_type);
    println!("miner value: {}", mt.value);
    println!("miner addr: {}", hex::encode(&mt.miner_address));
    println!("miner height: {}", mt.height);
    println!("miner payloads: {}", mt.payloads.len());
    // re-serialize and compare length
    let reser = blk.serialize(false);
    println!("reserialize len: {} orig: {}", reser.len(), raw.len());
    println!("roundtrip: {}", reser == raw);
}
