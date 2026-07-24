# 6. High-precision findings via forensicnomicon::report, observations not verdicts

Date: 2026-07-24
Status: Accepted

## Context

Amcache inventories *everything* Windows catalogued — most of it benign. An
analyzer that flagged large swaths of ordinary inventory would drown the signal and
train examiners to ignore it. The fleet mandates a single normalized reporting
model (`ronin-issen/CLAUDE.md`, "The Reporting Model — forensicnomicon::report") so
Issue/disk4n6 and a future GUI render every analyzer's output uniformly, and it
mandates that findings are **observations, never legal conclusions**. Amcache is
also evidence of *presence*, not proof of *execution* (it inventories installed and
scanned files too), which caps how strongly any finding may be phrased.

Evidence: `forensic/src/lib.rs` — `AmcacheAnomaly` with two variants; `impl
Observation` supplying `severity`/`category`/`code`/`note`/`mitre`/`subjects`; the
module doc ("a small set of *high-precision* graded findings"); the constructors
reuse `forensicnomicon::processes::is_system32_binary` and
`forensicnomicon::heuristics::paths::is_suspicious_exec_path` — shared fleet
knowledge, not a local allow-list; the README Findings table.

## Decision

1. **Only two, high-precision codes** — `AMCACHE-SYSTEM-BINARY-RELOCATED`
   (High, `Concealment`, `T1036.005`: a Windows system-binary name at a
   non-System32/SysWOW64 path) and `AMCACHE-SUSPICIOUS-PATH` (Medium, `Threat`,
   `T1204`: an executable inventoried from a known staging directory). The analyzer
   stays quiet on benign inventory.
2. **Emit through `forensicnomicon::report`** via `impl Observation` for
   `AmcacheAnomaly`, so `to_finding` produces the canonical `Finding` the whole
   fleet aggregates — no bespoke `AmcacheAnalysis` type.
3. **Codes are a published SCREAMING-KEBAB contract** (`AMCACHE-…`) — never changed
   once shipped; new variants get new codes.
4. **The SHA-1 rides every finding as a hash `SubjectRef`** alongside the file
   path, so a graded finding is directly pivotable.
5. **Reuse fleet heuristics** (`is_system32_binary`, `is_suspicious_exec_path`)
   rather than a local list, so the definition of "system binary" and "staging
   directory" stays consistent across analyzers.
6. **Language is "consistent with", never a verdict** — every `note()` ends
   "consistent with masquerading" / "consistent with suspicious execution"; the
   library docs state Amcache proves presence, not execution.

## Consequences

- Findings drop into Issen's unified `Report` with no adapter.
- Precision over recall: the analyzer is a triage signal, not an exhaustive
  classifier; broad enumeration is the CLI's `--files`/`--devices` job.
- Improving the shared heuristics improves this analyzer without a code change here.
