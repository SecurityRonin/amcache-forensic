# amcache-forensic

[![CI](https://github.com/SecurityRonin/amcache-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/amcache-forensic/actions)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Prove what was on a Windows box — with a SHA-1 to pivot on — straight from `Amcache.hve`, on any OS.** A panic-free reader for the modern (Windows 10/11) Amcache schema plus an analyzer that flags masquerading and staging-directory execution, every finding carrying the file hash.

## Run it

```console
$ cargo install amcache-forensic          # installs the amcache4n6 binary
$ amcache4n6 /path/to/Amcache.hve
Amcache: 123 file entries, 189 device entries
Findings (4):
  [MEDIUM] AMCACHE-SUSPICIOUS-PATH  c:\users\testuser\downloads\sysmon\sysmon64.exe
    sysmon64.exe at c:\users\testuser\downloads\sysmon\sysmon64.exe (SHA-1 71f5e906848b8e94e951551a08a4c9a045f19a03) sits in a directory commonly used to stage malware — consistent with suspicious execution.
  [MEDIUM] AMCACHE-SUSPICIOUS-PATH  c:\users\testuser\appdata\local\temp\…\ninite.exe
    ninite.exe … (SHA-1 ba7f0b553fe4eb017d2a2b2451f7a3e6ff2b521d) …
```

`--files` lists every inventoried executable (path, SHA-1, record time); `--devices` lists the PnP/USB devices.

## What it decodes

The modern **Windows 10/11** Amcache schema (`C:\Windows\AppCompat\Programs\Amcache.hve`):

- **`InventoryApplicationFile`** → `AmcacheFileEntry` — per inventoried executable: path, **SHA-1** (the `FileId` with its `0000` padding removed), publisher, version, product, binary type, size, and the record's `FILETIME`.
- **`InventoryDevicePnp`** → `AmcacheDeviceEntry` — PnP/USB devices: description, hardware id, manufacturer, model, class.

The pre-1607 `Root\File` layout (Windows 8/8.1, Server 2012 R2) is **detected and named**, not silently mis-read.

> **Amcache is evidence of *presence*, not proof of *execution*** — it also inventories files that were installed or scanned. Its value is the path plus a hash to identify the file. Findings are observations ("consistent with …"), never verdicts.

## Layers

- **`amcache-core`** — `parse_bytes(&[u8]) -> Amcache`. Walks the hive with [`winreg-core`], `#![forbid(unsafe_code)]`, panic-free.
- **`amcache-forensic`** — `analyze_bytes` + `audit` (graded `forensicnomicon` findings, each with the SHA-1 as a hash subject) and the `amcache4n6` CLI.

## Validation

Tier-1 against **real DFIRArtifactMuseum hives** (MIT) from **four Windows systems**, cross-checked with **two independent oracles** — Eric Zimmerman's `AmcacheParser` and `regipy`:

| Hive | Files | Devices |
|---|---|---|
| Win10 (APTSimulatorVM) | 123 | 189 |
| Win10 (RathbunVM) | 183 | 185 |
| Win11 (RathbunVM) | 231 | 187 |
| Server 2012 R2 (legacy schema) | — detected & named — | |

`7z.exe` → SHA-1 `1189cebeb8ffed7316f98b895ff949a726f4026f`, `CompatTelRunner.exe` → `77f2e744…` — matching both oracles byte-for-byte. See `core/tests/data/README.md`.

## Findings

| Code | Severity | MITRE | Fires when |
|---|---|---|---|
| `AMCACHE-SYSTEM-BINARY-RELOCATED` | High | T1036.005 | A Windows system-binary name recorded at a non-`System32` path (masquerading). |
| `AMCACHE-SUSPICIOUS-PATH` | Medium | T1204 | An executable inventoried from a common staging directory (Temp, Downloads, `$Recycle.Bin`, …). |

---

[Privacy Policy](https://securityronin.github.io/amcache-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/amcache-forensic/terms/) · © 2026 Security Ronin Ltd
