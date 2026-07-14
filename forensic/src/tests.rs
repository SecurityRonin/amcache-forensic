//! Unit tests: audit heuristics, the `Observation` mapping, and `analyze_bytes` on the real
//! committed Win10 APT-simulator hive.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

/// The real Win10 APTSimulatorVM hive (the same fixture amcache-core validates against).
const WIN10: &[u8] = include_bytes!("../../core/tests/data/amcache_win10.hve");

fn file(path: &str, sha1: Option<&str>) -> AmcacheFileEntry {
    AmcacheFileEntry {
        key_name: format!("{}|deadbeef", base_name(path)),
        name: Some(base_name(path)),
        full_path: Some(path.to_string()),
        sha1: sha1.map(str::to_string),
        ..Default::default()
    }
}

fn amcache_of(files: Vec<AmcacheFileEntry>) -> Amcache {
    Amcache {
        file_entries: files,
        device_entries: Vec::new(),
    }
}

#[test]
fn system_binary_at_non_system_path_flags_masquerading() {
    let am = amcache_of(vec![file(r"c:\temp\svchost.exe", Some("abc123"))]);
    let a = audit(&am);
    assert!(a.iter().any(|x| matches!(
        x,
        AmcacheAnomaly::SystemBinaryRelocated { name, sha1, .. }
            if name == "SVCHOST.EXE" && sha1.as_deref() == Some("abc123")
    )));
}

#[test]
fn system_binary_in_system32_is_not_flagged() {
    let am = amcache_of(vec![file(r"c:\windows\system32\svchost.exe", None)]);
    assert!(!audit(&am)
        .iter()
        .any(|x| matches!(x, AmcacheAnomaly::SystemBinaryRelocated { .. })));
}

#[test]
fn suspicious_path_is_flagged_with_its_hash() {
    let am = amcache_of(vec![file(
        r"c:\users\a\appdata\local\temp\dropper.exe",
        Some("f00d"),
    )]);
    match audit(&am)
        .into_iter()
        .find(|x| matches!(x, AmcacheAnomaly::SuspiciousPath { .. }))
    {
        Some(AmcacheAnomaly::SuspiciousPath { name, sha1, .. }) => {
            assert_eq!(name, "dropper.exe");
            assert_eq!(sha1.as_deref(), Some("f00d"));
        }
        other => panic!("expected SuspiciousPath, got {other:?}"),
    }
}

#[test]
fn benign_entry_and_pathless_entry_are_quiet() {
    let mut pathless = file(r"c:\x.exe", None);
    pathless.full_path = None;
    let am = amcache_of(vec![file(r"c:\program files\app\app.exe", None), pathless]);
    assert!(audit(&am).is_empty());
}

#[test]
fn observation_maps_all_fields() {
    for a in [
        AmcacheAnomaly::SystemBinaryRelocated {
            name: "SVCHOST.EXE".to_string(),
            path: r"c:\temp\svchost.exe".to_string(),
            sha1: Some("abc".to_string()),
        },
        AmcacheAnomaly::SuspiciousPath {
            name: "x.exe".to_string(),
            path: r"c:\temp\x.exe".to_string(),
            sha1: None,
        },
    ] {
        assert!(a.severity().is_some());
        assert!(!a.code().is_empty());
        assert!(!a.mitre().is_empty());
        assert!(!a.note().is_empty());
        assert!(!a.subjects().is_empty());
        let _ = to_finding(&a, "Amcache.hve");
    }
    // The relocated variant grades High/Concealment and includes the hash as a subject.
    let reloc = AmcacheAnomaly::SystemBinaryRelocated {
        name: "SVCHOST.EXE".to_string(),
        path: r"c:\temp\svchost.exe".to_string(),
        sha1: Some("abc".to_string()),
    };
    assert_eq!(reloc.severity(), Some(Severity::High));
    assert_eq!(reloc.category(), Category::Concealment);
    assert_eq!(reloc.mitre(), &["T1036.005"]);
    assert!(reloc.note().contains("SHA-1 abc"));
    assert!(reloc.subjects().iter().any(|s| s.scheme == "hash"));
}

#[test]
fn analyze_bytes_on_the_real_win10_hive() {
    let report = analyze_bytes(WIN10).unwrap();
    assert_eq!(report.amcache.file_entries.len(), 123);
    assert_eq!(report.amcache.device_entries.len(), 189);
    // A clean baseline inventory raises no false masquerading finding on this hive.
    assert!(!report
        .anomalies
        .iter()
        .any(|a| matches!(a, AmcacheAnomaly::SystemBinaryRelocated { .. })));
}

#[test]
fn analyze_bytes_rejects_non_amcache() {
    assert!(matches!(analyze_bytes(b"nope"), Err(AmcacheError::Hive(_))));
}
