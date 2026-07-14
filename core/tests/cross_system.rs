//! Cross-system validation: parse `Amcache.hve` files from several Windows versions and confirm
//! the entry counts match the `regipy` raw subkey counts. Env-gated — point each variable at a
//! DFIRArtifactMuseum `Amcache.hve` (`Windows/Amcache/<ver>/<vm>/Amcache.hve`):
//!
//! - `AMCACHE_TEST_WIN10_RATHBUN`  → 183 file / 185 device entries
//! - `AMCACHE_TEST_WIN11_RATHBUN`  → 231 file / 187 device entries
#![allow(clippy::unwrap_used)]

fn check(env: &str, files: usize, devices: usize) {
    let Ok(path) = std::env::var(env) else {
        eprintln!("SKIP: set {env} to the corresponding Amcache.hve");
        return;
    };
    let bytes = std::fs::read(&path).unwrap();
    let am = amcache_core::parse_bytes(&bytes).unwrap();
    assert_eq!(am.file_entries.len(), files, "{env}: file entry count");
    assert_eq!(
        am.device_entries.len(),
        devices,
        "{env}: device entry count"
    );
    // Every file entry has a key name; some carry a SHA-1 and a full path.
    assert!(am.file_entries.iter().all(|e| !e.key_name.is_empty()));
    assert!(am.file_entries.iter().any(|e| e.sha1.is_some()));
}

#[test]
fn win10_rathbun_matches_regipy_counts() {
    check("AMCACHE_TEST_WIN10_RATHBUN", 183, 185);
}

#[test]
fn win11_rathbun_matches_regipy_counts() {
    check("AMCACHE_TEST_WIN11_RATHBUN", 231, 187);
}
