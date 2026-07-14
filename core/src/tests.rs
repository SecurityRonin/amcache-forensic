//! Tier-1 validation against real DFIRArtifactMuseum Amcache hives (MIT), cross-checked with
//! Eric Zimmerman's `AmcacheParser` and `regipy`. See `tests/data/README.md`.

use super::*;

const WIN10: &[u8] = include_bytes!("../tests/data/amcache_win10.hve");
const OLD_2012R2: &[u8] = include_bytes!("../tests/data/amcache_2012r2_old.hve");
/// A real but non-Amcache hive (a CFReDS NTUSER.DAT) — no `Root\InventoryApplicationFile`
/// and no `Root\File`, so it exercises the `NotAmcache` path.
const NOT_AMCACHE: &[u8] = include_bytes!("../tests/data/not_amcache.hve");

#[test]
fn win10_hive_decodes_file_and_device_entries() {
    let am = parse_bytes(WIN10).unwrap();
    // 123 InventoryApplicationFile subkeys, 189 InventoryDevicePnp (both oracles agree).
    assert_eq!(am.file_entries.len(), 123);
    assert_eq!(am.device_entries.len(), 189);
}

#[test]
fn win10_7zip_entry_matches_the_oracle() {
    let am = parse_bytes(WIN10).unwrap();
    let e = am
        .file_entries
        .iter()
        .find(|e| e.key_name.starts_with("7z.exe|"))
        .expect("7z.exe entry");
    assert_eq!(e.name.as_deref(), Some("7z.exe"));
    assert_eq!(
        e.full_path.as_deref(),
        Some(r"c:\program files\7-zip\7z.exe")
    );
    // FileId 00001189… → SHA-1 last-40 (AmcacheParser + a from-FileId read agree).
    assert_eq!(
        e.sha1.as_deref(),
        Some("1189cebeb8ffed7316f98b895ff949a726f4026f")
    );
    assert!(e.key_last_written_filetime > 0);
}

#[test]
fn win10_system_binary_sha1_matches_the_oracle() {
    let am = parse_bytes(WIN10).unwrap();
    let e = am
        .file_entries
        .iter()
        .find(|e| e.name.as_deref() == Some("CompatTelRunner.exe"))
        .expect("CompatTelRunner.exe entry");
    assert_eq!(
        e.sha1.as_deref(),
        Some("77f2e744c92417653b5abd6ccb3b5e521111979a")
    );
    assert_eq!(
        e.full_path.as_deref(),
        Some(r"c:\windows\system32\compattelrunner.exe")
    );
}

#[test]
fn win10_device_entries_carry_a_description() {
    let am = parse_bytes(WIN10).unwrap();
    // Every device entry has a key name and a recorded write time; most carry a description.
    assert!(am.device_entries.iter().all(|d| !d.key_name.is_empty()));
    assert!(am
        .device_entries
        .iter()
        .any(|d| d.description.is_some() || d.bus_description.is_some()));
}

#[test]
fn legacy_root_file_schema_is_named_not_mis_read() {
    // The Server 2012 R2 hive uses the pre-1607 Root\File schema.
    match parse_bytes(OLD_2012R2) {
        Err(AmcacheError::OldSchemaUnsupported) => {}
        other => panic!("expected OldSchemaUnsupported, got {other:?}"),
    }
    assert!(parse_bytes(OLD_2012R2)
        .unwrap_err()
        .to_string()
        .contains("Root\\File"));
}

#[test]
fn non_hive_bytes_error_cleanly() {
    let err = parse_bytes(b"not a hive").unwrap_err();
    assert!(matches!(err, AmcacheError::Hive(_)));
    assert!(err.to_string().contains("hive error"));
}

#[test]
fn a_non_amcache_hive_is_named_not_amcache() {
    let err = parse_bytes(NOT_AMCACHE).unwrap_err();
    assert!(matches!(err, AmcacheError::NotAmcache));
    assert!(err.to_string().contains("not an Amcache hive"));
}

#[test]
fn parse_int_le_handles_dword_qword_and_short() {
    assert_eq!(parse_int_le(&[0x00, 0x4A, 0, 0, 0, 0, 0, 0]), Some(18944)); // qword
    assert_eq!(parse_int_le(&[0x00, 0x4A, 0, 0]), Some(18944)); // dword
    assert_eq!(parse_int_le(&[1, 2]), None); // too short
}

#[test]
fn sha1_from_file_id_strips_the_leading_padding() {
    assert_eq!(
        sha1_from_file_id("00001189cebeb8ffed7316f98b895ff949a726f4026f").as_deref(),
        Some("1189cebeb8ffed7316f98b895ff949a726f4026f")
    );
    // Too short to hold a digest → None.
    assert_eq!(sha1_from_file_id("0000"), None);
    // Already 40 chars → returned as-is (lower-cased).
    assert_eq!(
        sha1_from_file_id("ABCDEF0000000000000000000000000000000000").as_deref(),
        Some("abcdef0000000000000000000000000000000000")
    );
}
