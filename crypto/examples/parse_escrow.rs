use dero_crypto::dvm::parse_smart_contract;

fn main() {
    // test the specific expressions that might fail at runtime
    let tests = [
        "Function T1(id String) Uint64\n10 IF EXISTS(\"swap_\" + id + \"_maker\") THEN GOTO 100\n20 RETURN 1\n100 RETURN 0\nEnd Function",
        "Function T2(id String) Uint64\n10 STORE(\"swap_\" + id + \"_state\", 0)\n20 RETURN 1\nEnd Function",
        "Function T3() Uint64\n10 IF LOAD(\"k\") == SIGNER() THEN GOTO 50\n20 GOTO 100\n50 RETURN 1\n100 RETURN 0\nEnd Function",
    ];
    for (i, code) in tests.iter().enumerate() {
        match parse_smart_contract(code) {
            Ok(_) => println!("test {}: PARSE OK", i + 1),
            Err(e) => println!("test {}: FAIL {e}", i + 1),
        }
    }
}
