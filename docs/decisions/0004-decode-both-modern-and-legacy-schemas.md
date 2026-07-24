# 4. Decode both the modern and legacy Amcache schemas, auto-detected

Date: 2026-07-24
Status: Accepted

## Context

Amcache changed layout across Windows versions. Windows 10 1607+ and Windows 11
store execution/presence evidence under `Root\InventoryApplicationFile` (named
values: `Name`, `LowerCaseLongPath`, `FileId`, …) plus a `Root\InventoryDevicePnp`
device inventory. Windows 8/8.1 and Server 2012 R2 use the older
`Root\File\{volume-GUID}\{file-reference}` layout with **numbered** values
(`15`=path, `101`=SHA-1, `100`=program id, `0`=product, `1`=publisher) and carry no
device inventory.

The crate initially decoded the modern schema only (commit `65adb52`,
"Amcache modern-schema decoder"). Legacy support was added later as a distinct
TDD cycle (commit `5edf80e` RED, `70cb083` GREEN — "decode the legacy Root\File
Amcache schema"), which reworked `parse_bytes` to branch on schema. An examiner
handed a 2012 R2 or Windows 8 hive would otherwise get `NotAmcache` on a perfectly
valid artifact — a correctness gap, not a scope choice.

Evidence: `core/src/lib.rs` `parse_bytes` if/else on
`open_key("Root\\InventoryApplicationFile")` vs `open_key("Root\\File")`;
`read_legacy_file_entries` mapping numeric value names; the `AmcacheSchema` enum;
the four-system validation table in `docs/validation.md` including "Server 2012 R2
(Stolen Szechuan) — legacy `Root\File`".

## Decision

1. **Auto-detect the schema from key presence**, not from a version flag: presence
   of `Root\InventoryApplicationFile` ⇒ `Modern`; otherwise `Root\File` ⇒ `Legacy`;
   neither ⇒ `AmcacheError::NotAmcache`. No caller input, no guessing from a hint.
2. **Normalize both schemas into the same `AmcacheFileEntry`** so downstream code
   (the analyzer, the CLI) is schema-agnostic. Legacy-only gaps are `None`
   (`version`, `binary_type`, `size`), and the legacy `name` is derived from the
   path via `base_name` since the old layout has no `Name` value.
3. **`Amcache::schema` reports which layout was found**, so an examiner can see
   whether a device inventory is genuinely empty (legacy) or merely absent.

## Consequences

- The tool works across the full Windows 8 → 11 / Server 2012 R2+ range from one
  entry point.
- The general "map value-name → field" rule handles both schemas; there is no
  per-hive special-casing.
- Legacy hives report an empty `device_entries` by construction, which the CLI and
  README document as expected rather than a parse failure.
