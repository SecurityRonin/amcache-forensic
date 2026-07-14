//! Windows **Amcache.hve** forensic analyzer.
//!
//! Amcache is application-compatibility inventory — strong **evidence of presence** (and, with
//! its `SHA-1`, a hash to pivot on) for every executable Windows catalogued. [`analyze_bytes`]
//! decodes a hive with [`amcache_core`] and [`audit`] adds a small set of *high-precision* graded
//! findings: a Windows system-binary name recorded at a non-`System32` path (masquerading) and an
//! executable inventoried from a known-suspicious directory.
//!
//! Findings are observations, never verdicts: Amcache establishes that a file with a given path
//! and hash was present on the system — whether it is malicious is a correlation/tribunal
//! question. Amcache presence is **not** proof of execution (it also inventories files that were
//! merely installed or scanned); it is proof the file existed, with a hash to identify it.
//!
//! Built on [`amcache_core`]; findings use [`forensicnomicon::report`].

#![forbid(unsafe_code)]

use forensicnomicon::report::{Category, Finding, Observation, Severity, Source, SubjectRef};

// Re-export the core types that appear in this crate's public API.
pub use amcache_core::{
    Amcache, AmcacheDeviceEntry, AmcacheError, AmcacheFileEntry, AmcacheSchema,
};

/// The result of analyzing an Amcache hive.
#[derive(Debug, Clone)]
pub struct AmcacheReport {
    /// The decoded hive (file + device entries).
    pub amcache: Amcache,
    /// Graded anomalies (may be empty).
    pub anomalies: Vec<AmcacheAnomaly>,
}

/// A graded Amcache finding — a *high-precision* triage signal that stays quiet on benign
/// inventory and fires only on a genuinely anomalous pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AmcacheAnomaly {
    /// A Windows system-binary *name* recorded at a path that is not under `System32`/`SysWOW64`
    /// — consistent with masquerading (`T1036.005`).
    SystemBinaryRelocated {
        /// The system-binary base name (e.g. `SVCHOST.EXE`).
        name: String,
        /// The full path Amcache recorded.
        path: String,
        /// The file's `SHA-1`, if Amcache recorded one.
        sha1: Option<String>,
    },
    /// An executable inventoried from a directory commonly used to stage malware (Temp,
    /// Downloads, `$Recycle.Bin`, …) — `T1204`.
    SuspiciousPath {
        /// The executable base name.
        name: String,
        /// The suspicious path.
        path: String,
        /// The file's `SHA-1`, if Amcache recorded one.
        sha1: Option<String>,
    },
}

/// Decode an Amcache hive from bytes and audit it.
///
/// # Errors
/// [`AmcacheError`] if the bytes are not a readable Amcache hive (or use the unsupported legacy
/// schema — see [`amcache_core`]).
pub fn analyze_bytes(bytes: &[u8]) -> Result<AmcacheReport, AmcacheError> {
    let amcache = amcache_core::parse_bytes(bytes)?;
    let anomalies = audit(&amcache);
    Ok(AmcacheReport { amcache, anomalies })
}

/// Audit a decoded Amcache for graded anomalies (may be empty).
#[must_use]
pub fn audit(amcache: &Amcache) -> Vec<AmcacheAnomaly> {
    let mut out = Vec::new();
    for e in &amcache.file_entries {
        let Some(path) = e.full_path.as_deref() else {
            continue;
        };
        let name = base_name(path);
        let upper = path.to_uppercase();
        let in_system = upper.contains(r"\SYSTEM32\") || upper.contains(r"\SYSWOW64\");
        if forensicnomicon::processes::is_system32_binary(&name) && !in_system {
            out.push(AmcacheAnomaly::SystemBinaryRelocated {
                name: name.to_uppercase(),
                path: path.to_string(),
                sha1: e.sha1.clone(),
            });
        }
        if forensicnomicon::heuristics::paths::is_suspicious_exec_path(path) {
            out.push(AmcacheAnomaly::SuspiciousPath {
                name,
                path: path.to_string(),
                sha1: e.sha1.clone(),
            });
        }
    }
    out
}

/// The base name (last `\`/`/`-component) of a path.
fn base_name(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

impl AmcacheAnomaly {
    fn fields(&self) -> (&str, &str, Option<&str>) {
        match self {
            AmcacheAnomaly::SystemBinaryRelocated { name, path, sha1 }
            | AmcacheAnomaly::SuspiciousPath { name, path, sha1 } => (name, path, sha1.as_deref()),
        }
    }
}

impl Observation for AmcacheAnomaly {
    fn severity(&self) -> Option<Severity> {
        Some(match self {
            AmcacheAnomaly::SystemBinaryRelocated { .. } => Severity::High,
            AmcacheAnomaly::SuspiciousPath { .. } => Severity::Medium,
        })
    }

    fn category(&self) -> Category {
        match self {
            AmcacheAnomaly::SystemBinaryRelocated { .. } => Category::Concealment,
            AmcacheAnomaly::SuspiciousPath { .. } => Category::Threat,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            AmcacheAnomaly::SystemBinaryRelocated { .. } => "AMCACHE-SYSTEM-BINARY-RELOCATED",
            AmcacheAnomaly::SuspiciousPath { .. } => "AMCACHE-SUSPICIOUS-PATH",
        }
    }

    fn note(&self) -> String {
        let (name, path, sha1) = self.fields();
        let hash = sha1.map_or_else(String::new, |h| format!(" (SHA-1 {h})"));
        match self {
            AmcacheAnomaly::SystemBinaryRelocated { .. } => format!(
                "{name} is a Windows system binary, but Amcache recorded it at {path}{hash} \
                 — consistent with masquerading."
            ),
            AmcacheAnomaly::SuspiciousPath { .. } => format!(
                "{name} at {path}{hash} sits in a directory commonly used to stage malware \
                 — consistent with suspicious execution."
            ),
        }
    }

    fn mitre(&self) -> &'static [&'static str] {
        match self {
            AmcacheAnomaly::SystemBinaryRelocated { .. } => &["T1036.005"],
            AmcacheAnomaly::SuspiciousPath { .. } => &["T1204"],
        }
    }

    fn subjects(&self) -> Vec<SubjectRef> {
        let (name, path, sha1) = self.fields();
        let mut subs = vec![SubjectRef {
            scheme: "filesystem".to_string(),
            kind: "executable".to_string(),
            id: path.to_string(),
            label: Some(name.to_string()),
        }];
        if let Some(h) = sha1 {
            subs.push(SubjectRef {
                scheme: "hash".to_string(),
                kind: "sha1".to_string(),
                id: h.to_string(),
                label: Some(name.to_string()),
            });
        }
        subs
    }
}

/// Convenience: produce a [`Finding`] for an anomaly under the given scope.
#[must_use]
pub fn to_finding(anomaly: &AmcacheAnomaly, scope: impl Into<String>) -> Finding {
    anomaly.to_finding(Source {
        analyzer: "amcache-forensic".to_string(),
        scope: scope.into(),
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
    })
}

#[cfg(test)]
mod tests;
