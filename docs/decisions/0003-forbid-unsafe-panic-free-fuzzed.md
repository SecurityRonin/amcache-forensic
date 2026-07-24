# 3. forbid(unsafe), panic-free by lint, and fuzzed for untrusted input

Date: 2026-07-24
Status: Accepted

## Context

Both crates parse an **attacker-controllable** artifact: a hive lifted from a
subject system can be truncated, corrupted, or crafted. The fleet's Paranoid
Gatekeeper standard (`ronin-issen/CLAUDE.md`, "Security & Robustness Standard")
requires every `*-core`/`*-forensic` crate to never panic, never read out of
bounds, and never trust a length field. Unlike the mmap readers (ewf,
memory-forensic) that must downgrade to `unsafe_code = "deny"` for a bounded
`Mmap::map`, this crate does no memory mapping and no raw pointer work — it operates
entirely over `&[u8]` and `winreg-core`'s safe API — so it can hold the stronger,
provable `forbid(unsafe)` posture.

Evidence: workspace `Cargo.toml` `[workspace.lints.rust] unsafe_code = "forbid"`
plus `unwrap_used`/`expect_used = "deny"`; `#![forbid(unsafe_code)]` at the top of
`core/src/lib.rs`, `forensic/src/lib.rs`, and `bin/amcache4n6.rs`; the README
`unsafe forbidden` badge; the fuzz kit added in commit `4ea24ae`
(`fuzz/fuzz_targets/fuzz_parse.rs`, `fuzz_forensic.rs`) with `fuzz.yml`.

## Decision

1. **`unsafe_code = "forbid"`** workspace-wide — the strongest, non-overridable
   memory-safety guarantee, earned because nothing here needs `unsafe`.
2. **Panic-free by lint** — `unwrap_used`/`expect_used` are hard denies in
   production; every registry read is fallible and propagated (`str_value`,
   `int_value` return `Option`; `parse_bytes` returns `Result<_, AmcacheError>`).
   `clippy.toml` re-enables unwrap/expect in tests only.
3. **Fail loud on "not an Amcache hive"** — a hive with neither
   `InventoryApplicationFile` nor `Root\File` returns `AmcacheError::NotAmcache`,
   never a silently-empty success (Fail-loud / bootstrap-failure discipline).
4. **One fuzz target per parsed surface** — `fuzz_parse` drives
   `amcache_core::parse_bytes`; `fuzz_forensic` drives `analyze_bytes` (decode +
   audit), covering the full untrusted-input pipeline.

## Decision follows the evidence-based robustness wording

The README leads with the *measured* claim ("panic-free-by-construction",
fuzzed) and keeps "panic-free" as the static, lint-enforced half — never a bare
unprovable universal, per the fleet's robustness-wording rule.

## Consequences

- The repo can wear the `unsafe forbidden` badge honestly (no `deny`+allow
  exceptions to enumerate).
- Malformed or hostile hives yield a typed error, never a crash or wrong output.
- Adding a new parsed structure means adding a matching fuzz target.
