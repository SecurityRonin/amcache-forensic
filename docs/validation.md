# Validation

`amcache-core` is validated against **real DFIRArtifactMuseum hives** (MIT) from four Windows
systems, cross-checked with **two independent oracles** — Eric Zimmerman's `AmcacheParser` and
`regipy`.

## Tier-1 (real data + independent oracles)

| Hive | Schema | Files | Devices |
|---|---|---|---|
| Windows 10 (APTSimulatorVM) | modern | 123 | 189 |
| Windows 10 (RathbunVM) | modern | 183 | 185 |
| Windows 11 (RathbunVM) | modern | 231 | 187 |
| Server 2012 R2 (Stolen Szechuan) | legacy `Root\File` | 136 | — |

Both oracles agree with `amcache-core` on every count. Sample hashes match byte-for-byte:
`7z.exe` → `1189cebeb8ffed7316f98b895ff949a726f4026f` (modern), `vm3dservice.exe` →
`f0032dfb7e5d67dd10568e61787a4a3032ff55f5` (legacy). `AmcacheParser` is run with `--nl` (no
transaction-log replay) to match a plain hive read.

The `SHA-1` is the `FileId`/`101` value with its leading `0000` padding removed (the last 40 hex
chars). Committed fixtures and provenance are in `core/tests/data/README.md`.
