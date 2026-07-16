//! Fuzz target: feed arbitrary bytes as an Amcache hive to the reader.
//! Invariant: `parse_bytes` never panics — malformed / non-hive input yields a typed error,
//! and hive walking is bounds-checked (no unwrap, no out-of-bounds index).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = amcache_core::parse_bytes(data);
});
