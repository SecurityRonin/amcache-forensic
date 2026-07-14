//! `amc4n6` — read a Windows `Amcache.hve` and print the inventoried executables (path, `SHA-1`)
//! and PnP devices, plus graded findings.
//!
//! Decoding + analysis live in the `amcache_forensic` / `amcache_core` libraries; this binary
//! reads the file and renders the result.
#![forbid(unsafe_code)]

use std::process::ExitCode;

use amcache_forensic::{analyze_bytes, AmcacheAnomaly, AmcacheReport};
use forensicnomicon::report::Observation;
use winreg_core::key::filetime_to_datetime;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let files = args.iter().any(|a| a == "--files");
    let devices = args.iter().any(|a| a == "--devices");
    let Some(path) = args.iter().find(|a| !a.starts_with("--")) else {
        eprintln!("usage: amc4n6 <Amcache.hve> [--files] [--devices]");
        return ExitCode::from(2);
    };

    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("amc4n6: {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    match analyze_bytes(&bytes) {
        Ok(report) => {
            print_report(&report, files, devices);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("amc4n6: {path}: {e}");
            ExitCode::FAILURE
        }
    }
}

fn print_report(report: &AmcacheReport, files: bool, devices: bool) {
    println!(
        "Amcache: {} file entries, {} device entries",
        report.amcache.file_entries.len(),
        report.amcache.device_entries.len()
    );

    if report.anomalies.is_empty() {
        println!("Findings: none");
    } else {
        println!("Findings ({}):", report.anomalies.len());
        for a in &report.anomalies {
            let sev = a
                .severity()
                .map_or_else(|| "INFO".to_string(), |s| format!("{s:?}").to_uppercase());
            println!("  [{sev}] {}  {}", a.code(), subject_path(a));
            println!("    {}", a.note());
        }
    }

    if files {
        println!("\nInventoried executables:");
        for e in &report.amcache.file_entries {
            let when = filetime_to_datetime(e.key_last_written_filetime)
                .map_or_else(|| "-".to_string(), |t| t.to_string());
            println!(
                "  {when}  {}  {}",
                e.sha1.as_deref().unwrap_or("-".repeat(40).as_str()),
                e.full_path.as_deref().unwrap_or(&e.key_name)
            );
        }
    }

    if devices {
        println!("\nInventoried devices:");
        for d in &report.amcache.device_entries {
            let desc = d
                .bus_description
                .as_deref()
                .or(d.description.as_deref())
                .unwrap_or("-");
            println!("  {desc}  [{}]", d.hwid.as_deref().unwrap_or("-"));
        }
    }
}

fn subject_path(a: &AmcacheAnomaly) -> &str {
    match a {
        AmcacheAnomaly::SystemBinaryRelocated { path, .. }
        | AmcacheAnomaly::SuspiciousPath { path, .. } => path,
    }
}
