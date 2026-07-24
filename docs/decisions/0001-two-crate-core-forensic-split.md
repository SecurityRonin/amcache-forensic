# 1. Two-crate core/forensic split (reader vs analyzer)

Date: 2026-07-24
Status: Accepted

## Context

Amcache is a single artifact family — one registry hive
(`C:\Windows\AppCompat\Programs\Amcache.hve`). The fleet's binding
Crate-structure standard (`ronin-issen/CLAUDE.md`, "Crate-structure standard —
reader/analyzer split") mandates that every single-format repo is **Pattern A**:
one workspace named `<x>-forensic` with exactly two members — `<x>-core` (the raw
reader) and `<x>-forensic` (the anomaly analyzer). The reader is built to read
valid data robustly; the analyzer emits graded findings. Keeping them in one crate
would force third-party consumers who only want to *decode* a hive to pull the
whole finding/reporting stack, and would blur the reader's low-MSRV promise with
the analyzer's heavier dependencies.

Evidence: workspace `Cargo.toml` `members = ["core", "forensic"]`; the TDD commit
sequence built the reader first (`c9d9c1b`/`65adb52` core RED/GREEN) then the
analyzer (`5c5dbae`/`ca381e8` forensic RED/GREEN).

## Decision

1. **`amcache-core`** owns decoding only: `parse_bytes(&[u8]) -> Amcache` and the
   typed entries (`AmcacheFileEntry`, `AmcacheDeviceEntry`, `AmcacheSchema`). No
   findings, no severity, no MITRE — pure format knowledge
   (`core/src/lib.rs`).
2. **`amcache-forensic`** depends **down** on `amcache-core`
   (`forensic/Cargo.toml` → `amcache-core = { workspace = true }`), decodes via
   `amcache_core::parse_bytes`, and adds `audit()` + the graded `AmcacheAnomaly`
   findings. It re-exports the core types that appear in its public API so a
   consumer needs only one crate.
3. The dependency direction is one-way (`forensic → core`), never the reverse.
   The forensic layer here builds *on* the core reader (not below it), because the
   `Amcache` decoded model already exposes everything the audit needs — full paths,
   SHA-1, publisher. The fleet standard permits an analyzer to drop below `-core`
   only when the reader hides the anomaly being hunted; that is not the case for
   Amcache, whose evidence is the decoded key/value fields, not raw slack.

## Consequences

- A third-party tool that only wants to read a hive depends on `amcache-core`
  alone and never links the reporting stack.
- New finding types are added in `amcache-forensic` without touching the reader.
- The split matches the migrated fleet references (ntfs-forensic, vmdk-forensic,
  qcow2-forensic), so a fleet reader knows the layout on sight.
