//! Pure-Rust read-only reader for the modern (Windows 10/11) **Amcache.hve** schema.
//!
//! Amcache is an application-compatibility database — a registry hive at
//! `C:\Windows\AppCompat\Programs\Amcache.hve`. Its `Root\InventoryApplicationFile` subkeys are
//! **execution/presence evidence** for every executable Windows inventoried: the file's path,
//! `SHA-1`, publisher, size, and link date. `Root\InventoryDevicePnp` records PnP/USB devices.
//! This crate decodes both into typed entries. It walks the hive with [`winreg_core`]; it never
//! writes, is `#![forbid(unsafe_code)]`, and is panic-free (every registry read is fallible and
//! propagated, never unwrapped).
//!
//! Both schemas are decoded: the **modern** one (Windows 10 1607+ / Windows 11), whose entries
//! live under `Root\InventoryApplicationFile`, and the **legacy** pre-1607 layout
//! (`Root\File\{volume-GUID}\…`, numbered values, used by Windows 8/8.1 and Server 2012 R2).
//! [`Amcache::schema`] reports which was found. Legacy hives carry no `InventoryDevicePnp`, so
//! their device list is empty; modern hives populate both.
//!
//! Field semantics follow libyal's `dtformats` "AMCache.hve format" documentation and are
//! cross-validated against Eric Zimmerman's `AmcacheParser` and `regipy` (see `tests/`). The
//! `SHA-1` is the `FileId` value with its leading `0000` padding removed (its last 40 hex chars).

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::io::Cursor;

use winreg_core::error::HiveError;
use winreg_core::hive::Hive;
use winreg_core::key::Key;

/// One `InventoryApplicationFile` entry — an executable Windows inventoried (execution/presence
/// evidence).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AmcacheFileEntry {
    /// The subkey name — a `<name>|<LongPathHash>` token uniquely keying the file.
    pub key_name: String,
    /// The file name (`Name`), e.g. `7z.exe`.
    pub name: Option<String>,
    /// The full lower-case path (`LowerCaseLongPath`).
    pub full_path: Option<String>,
    /// The file's `SHA-1` (the `FileId` value with its leading `0000` padding removed); `None`
    /// when Amcache recorded no hash (common for Store/AppX binaries).
    pub sha1: Option<String>,
    /// The associated program id (`ProgramId`), linking to an `InventoryApplication` entry.
    pub program_id: Option<String>,
    /// The signing publisher (`Publisher`).
    pub publisher: Option<String>,
    /// The file version (`Version`).
    pub version: Option<String>,
    /// The product name (`ProductName`).
    pub product_name: Option<String>,
    /// The binary type (`BinaryType`), e.g. `pe64_amd64`.
    pub binary_type: Option<String>,
    /// The file size in bytes (`Size`).
    pub size: Option<u64>,
    /// The subkey's last-written time as a raw Windows `FILETIME` — when Amcache recorded the
    /// entry (a distinct timestamp from the file's own link date).
    pub key_last_written_filetime: u64,
}

/// One `InventoryDevicePnp` entry — a PnP / USB device Windows inventoried.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AmcacheDeviceEntry {
    /// The subkey name (a device-instance token).
    pub key_name: String,
    /// Human-readable description (`Description`).
    pub description: Option<String>,
    /// Bus-reported description (`BusReportedDescription`) — often the friendly device name.
    pub bus_description: Option<String>,
    /// The first hardware id (`HWID`).
    pub hwid: Option<String>,
    /// The manufacturer (`Manufacturer`).
    pub manufacturer: Option<String>,
    /// The model (`Model`).
    pub model: Option<String>,
    /// The device setup class (`Class`).
    pub class: Option<String>,
    /// The subkey's last-written time as a raw Windows `FILETIME`.
    pub key_last_written_filetime: u64,
}

/// A decoded Amcache hive.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Amcache {
    /// Which schema the hive used.
    pub schema: AmcacheSchema,
    /// File entries (`InventoryApplicationFile` on modern hives, `Root\File\{volume}\…` on legacy).
    pub file_entries: Vec<AmcacheFileEntry>,
    /// `InventoryDevicePnp` entries (modern schema only; empty on legacy hives).
    pub device_entries: Vec<AmcacheDeviceEntry>,
}

/// Which Amcache schema a hive uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AmcacheSchema {
    /// Windows 10 1607+ / Windows 11 (`Root\InventoryApplicationFile`).
    #[default]
    Modern,
    /// Windows 8 / 8.1 / Server 2012 R2 (`Root\File\{volume-GUID}\…`, numbered values).
    Legacy,
}

/// A failure reading an Amcache hive.
#[derive(Debug)]
pub enum AmcacheError {
    /// The hive could not be parsed.
    Hive(HiveError),
    /// The hive has neither an `InventoryApplicationFile` nor a `File` key — not an Amcache hive.
    NotAmcache,
}

impl std::fmt::Display for AmcacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hive(e) => write!(f, "hive error: {e}"),
            Self::NotAmcache => write!(f, "hive has no Root key — not an Amcache hive"),
        }
    }
}

impl std::error::Error for AmcacheError {}

impl From<HiveError> for AmcacheError {
    fn from(e: HiveError) -> Self {
        Self::Hive(e)
    }
}

/// Parse an Amcache hive from its raw bytes (modern Windows 10/11 or legacy Windows 8/8.1/2012 R2).
///
/// # Errors
/// [`AmcacheError`] if the bytes are not a readable hive, or the hive is not an Amcache hive.
pub fn parse_bytes(bytes: &[u8]) -> Result<Amcache, AmcacheError> {
    let hive = Hive::from_bytes(bytes.to_vec())?;
    // The modern schema lives under Root\InventoryApplicationFile; the legacy one under Root\File.
    if let Some(iaf) = hive.open_key("Root\\InventoryApplicationFile")? {
        let file_entries = read_file_entries(&iaf)?;
        // A hive may carry InventoryApplicationFile but no InventoryDevicePnp — not an error.
        let device_entries = hive
            .open_key("Root\\InventoryDevicePnp")?
            .map(|pnp| read_device_entries(&pnp))
            .transpose()?
            .unwrap_or_default();
        Ok(Amcache {
            schema: AmcacheSchema::Modern,
            file_entries,
            device_entries,
        })
    } else if let Some(root_file) = hive.open_key("Root\\File")? {
        Ok(Amcache {
            schema: AmcacheSchema::Legacy,
            file_entries: read_legacy_file_entries(&root_file)?,
            device_entries: Vec::new(),
        })
    } else {
        Err(AmcacheError::NotAmcache)
    }
}

/// Legacy schema: `Root\File\{volume-GUID}\{file-reference}`, values named by hex code
/// (`15`=path, `101`=SHA-1, `100`=program id, `0`=product, `1`=publisher). Walk every volume.
fn read_legacy_file_entries(
    root_file: &Key<'_, Hive<Cursor<Vec<u8>>>>,
) -> Result<Vec<AmcacheFileEntry>, AmcacheError> {
    let mut out = Vec::new();
    for volume in root_file.subkeys()? {
        for sk in volume.subkeys()? {
            let full_path = str_value(&sk, "15");
            let name = full_path.as_deref().map(base_name);
            out.push(AmcacheFileEntry {
                key_name: sk.name(),
                name,
                full_path,
                sha1: str_value(&sk, "101").and_then(|id| sha1_from_file_id(&id)),
                program_id: str_value(&sk, "100"),
                publisher: str_value(&sk, "1"),
                version: None,
                product_name: str_value(&sk, "0"),
                binary_type: None,
                size: None,
                key_last_written_filetime: sk.last_written_raw(),
            });
        }
    }
    Ok(out)
}

/// The base name (last `\`/`/`-component) of a path.
fn base_name(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

fn read_file_entries(
    root: &Key<'_, Hive<Cursor<Vec<u8>>>>,
) -> Result<Vec<AmcacheFileEntry>, AmcacheError> {
    let mut out = Vec::new();
    for sk in root.subkeys()? {
        out.push(AmcacheFileEntry {
            key_name: sk.name(),
            name: str_value(&sk, "Name"),
            full_path: str_value(&sk, "LowerCaseLongPath"),
            sha1: str_value(&sk, "FileId").and_then(|id| sha1_from_file_id(&id)),
            program_id: str_value(&sk, "ProgramId"),
            publisher: str_value(&sk, "Publisher"),
            version: str_value(&sk, "Version"),
            product_name: str_value(&sk, "ProductName"),
            binary_type: str_value(&sk, "BinaryType"),
            size: int_value(&sk, "Size"),
            key_last_written_filetime: sk.last_written_raw(),
        });
    }
    Ok(out)
}

fn read_device_entries(
    root: &Key<'_, Hive<Cursor<Vec<u8>>>>,
) -> Result<Vec<AmcacheDeviceEntry>, AmcacheError> {
    let mut out = Vec::new();
    for sk in root.subkeys()? {
        out.push(AmcacheDeviceEntry {
            key_name: sk.name(),
            description: str_value(&sk, "Description"),
            bus_description: str_value(&sk, "BusReportedDescription"),
            hwid: str_value(&sk, "HWID"),
            manufacturer: str_value(&sk, "Manufacturer"),
            model: str_value(&sk, "Model"),
            class: str_value(&sk, "Class"),
            key_last_written_filetime: sk.last_written_raw(),
        });
    }
    Ok(out)
}

/// Read a value as a non-empty string; `None` if absent, unreadable, or empty.
fn str_value(key: &Key<'_, Hive<Cursor<Vec<u8>>>>, name: &str) -> Option<String> {
    let value = key.value(name).ok()??;
    let s = value.as_string().ok()?;
    // HWID and similar REG_MULTI_SZ come back with embedded NULs joined; keep the first line.
    let first = s.split(['\u{0}', '\n']).next().unwrap_or(&s).trim();
    (!first.is_empty()).then(|| first.to_string())
}

/// Read a value as an integer, tolerating both `REG_DWORD` (4-byte) and `REG_QWORD` (8-byte).
fn int_value(key: &Key<'_, Hive<Cursor<Vec<u8>>>>, name: &str) -> Option<u64> {
    let value = key.value(name).ok()??;
    parse_int_le(&value.raw_data().ok()?)
}

/// Decode a little-endian unsigned integer from a registry value's raw bytes: `REG_QWORD`
/// (≥ 8 bytes) or `REG_DWORD` (≥ 4 bytes). `None` if too short to hold either.
fn parse_int_le(data: &[u8]) -> Option<u64> {
    if let Some(b) = data.get(..8) {
        Some(u64::from_le_bytes(b.try_into().ok()?))
    } else if let Some(b) = data.get(..4) {
        Some(u64::from(u32::from_le_bytes(b.try_into().ok()?)))
    } else {
        None
    }
}

/// The `SHA-1` encoded in a `FileId` value: Amcache prefixes the 40-hex-char digest with `0000`,
/// so the hash is the last 40 characters. `None` when the id is too short to hold a digest.
fn sha1_from_file_id(file_id: &str) -> Option<String> {
    let id = file_id.trim();
    (id.len() >= 40).then(|| id[id.len() - 40..].to_ascii_lowercase())
}

#[cfg(test)]
mod tests;
