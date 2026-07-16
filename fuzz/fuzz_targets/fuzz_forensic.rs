//! Fuzz target: run the analyzer over arbitrary bytes as an Amcache hive.
//! Invariant: `analyze_bytes` never panics; findings are derived without unwrap.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = amcache_forensic::analyze_bytes(data);
});
