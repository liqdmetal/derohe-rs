use dero_crypto::rpc_args::Arguments;

fn main() {
    // the exact marshal from the wallet (291 bytes)
    let _hexdata = "aa636964536573776170316653434f4e53545055455354".to_string();
    // use the full 291 bytes — reconstruct from a marshal round-trip with the same args
    use dero_crypto::rpc_args::{ArgValue, Argument, DATA_HASH, DATA_STRING, DATA_UINT64};
    let args = Arguments(vec![
        Argument {
            name: "SC_ACTION".into(),
            data_type: DATA_UINT64,
            value: ArgValue::U64(0),
        },
        Argument {
            name: "SC_ID".into(),
            data_type: DATA_HASH,
            value: ArgValue::Hash([0x72u8; 32]),
        },
        Argument {
            name: "entrypoint".into(),
            data_type: DATA_STRING,
            value: ArgValue::Str("CreateSwap".into()),
        },
        Argument {
            name: "id".into(),
            data_type: DATA_STRING,
            value: ArgValue::Str("swap1".into()),
        },
        Argument {
            name: "sellToken".into(),
            data_type: DATA_STRING,
            value: ArgValue::Str("a1".repeat(32)),
        },
        Argument {
            name: "sellAmount".into(),
            data_type: DATA_UINT64,
            value: ArgValue::U64(100),
        },
        Argument {
            name: "buyToken".into(),
            data_type: DATA_STRING,
            value: ArgValue::Str("0".repeat(64)),
        },
        Argument {
            name: "buyAmount".into(),
            data_type: DATA_UINT64,
            value: ArgValue::U64(50),
        },
        Argument {
            name: "maker".into(),
            data_type: DATA_STRING,
            value: ArgValue::Str("wsrc".into()),
        },
        Argument {
            name: "timeout".into(),
            data_type: DATA_UINT64,
            value: ArgValue::U64(1000),
        },
    ]);
    let bytes = args.marshal_binary().unwrap();
    println!(
        "marshal {} bytes, head: {}",
        bytes.len(),
        hex::encode(&bytes[..40])
    );
    match Arguments::unmarshal_binary(&bytes) {
        Ok(back) => println!(
            "unmarshal OK: {} args, get_string(id)={:?}",
            back.0.len(),
            back.get_string("id")
        ),
        Err(e) => println!("unmarshal FAIL: {e}"),
    }
}
