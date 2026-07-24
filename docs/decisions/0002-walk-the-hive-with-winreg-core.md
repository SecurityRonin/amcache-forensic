# 2. Walk the hive with winreg-core rather than a bespoke REGF parser

Date: 2026-07-24
Status: Accepted

## Context

Amcache.hve is not a novel binary format — it **is** a Windows registry (REGF)
hive. Its schema is a tree of keys and values; decoding Amcache is walking that
tree and reading named values. The fleet already publishes a pure-Rust REGF hive
parser, `winreg-core`, and the binding Dependency-Preference rule
(`ronin-issen/CLAUDE.md`, "Dependency Preference — prefer our own crates") requires
using our own crate over a third party or a fresh reimplementation when an
equivalent exists. Hand-rolling a REGF parser inside `amcache-core` would duplicate
an audited, fuzzed fleet crate and re-introduce every hive-parsing bug class
`winreg-core` already solved.

Evidence: workspace `Cargo.toml` comment — "Generic REGF hive parser — Amcache IS
a hive, so core walks its schema with winreg-core." — and `winreg-core = "0.2"`;
`core/src/lib.rs` imports `winreg_core::{hive::Hive, key::Key, error::HiveError}`
and uses `Hive::from_bytes`, `open_key`, `subkeys`, `value`.

## Decision

1. `amcache-core` treats the hive as a `winreg_core::Hive` and expresses the whole
   Amcache schema as key navigation: `hive.open_key("Root\\InventoryApplicationFile")`,
   `open_key("Root\\InventoryDevicePnp")`, `open_key("Root\\File")`, then
   `subkeys()` + `value(name)`.
2. `amcache-core` owns **only Amcache-specific knowledge** — which keys exist per
   schema, which value names map to which fields, and how to decode a `FileId` into
   a SHA-1. All REGF byte-level concerns (cells, hbins, big-data, value types)
   stay in `winreg-core`.
3. Integer values are read tolerantly across `REG_DWORD`/`REG_QWORD`
   (`parse_int_le` in `core/src/lib.rs`) and multi-line strings collapse to the
   first line, because real hives carry `REG_MULTI_SZ` HWIDs — the reader adapts to
   the value types `winreg-core` surfaces rather than assuming one.

## Consequences

- Amcache inherits `winreg-core`'s robustness and fuzzing for free; this crate's
  own fuzz targets exercise only the Amcache-schema layer on top.
- A REGF fix or improvement lands once in `winreg-core` and benefits every fleet
  consumer, including this one.
- `amcache-core`'s own surface stays small — it is a schema walker, not a parser.
