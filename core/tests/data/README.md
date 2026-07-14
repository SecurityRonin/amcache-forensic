# amcache-core test data — provenance

Both hives are from **DFIRArtifactMuseum** (<https://github.com/AndrewRathbun/DFIRArtifactMuseum>,
`Windows/Amcache/`), **MIT-licensed** and freely redistributable.

| File | Source | Schema | MD5 |
|---|---|---|---|
| `amcache_win10.hve` | `Win10/APTSimulatorVM/Amcache.hve` | modern (`InventoryApplicationFile`) | `cc22b30f8410b607d107583fa6de8e53` |
| `amcache_2012r2_old.hve` | `Win2012R2/StolenSzechuan/Amcache.hve` | legacy (`Root\File`) | (Server 2012 R2) |

**Ground truth / oracles.** Cross-validated by two independent tools (`--nl`, no transaction-log
replay, to match a plain hive read):

- **Eric Zimmerman's `AmcacheParser`** (built from source, `dotnet`): on `amcache_win10.hve` —
  124 file entries (20 unassociated + 104 associated), 189 device PnPs, 12 device containers, 90
  program entries. Sample: `7z.exe` `SHA1=1189cebeb8ffed7316f98b895ff949a726f4026f` at
  `c:\program files\7-zip\7z.exe`; `CompatTelRunner.exe`
  `SHA1=77f2e744c92417653b5abd6ccb3b5e521111979a`.
- **`regipy`** (raw key/value cross-read): agrees — `Root\InventoryApplicationFile` = 123 subkeys,
  `Root\InventoryDevicePnp` = 189, `InventoryApplication` = 90, `InventoryDeviceContainer` = 12.

(The `AmcacheParser` "124" vs `regipy`/this-crate "123" differ by one associated record that
`AmcacheParser` derives from a program entry; both agree on the raw `InventoryApplicationFile`
subkey set.) `FileId` → `SHA-1`: the digest is the value's last 40 hex chars (leading `0000` is
padding).

Both hives are ≤ 1 MiB and MIT-licensed, so committed directly. The larger Win10/Win11 RathbunVM
hives are used via env-gated cross-system tests (`AMCACHE_TEST_HIVE_*`), not committed.
