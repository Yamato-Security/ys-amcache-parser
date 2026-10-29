//! Pure-Rust read-only reader for modern and legacy Windows **Amcache.hve** schemas.
//!
//! Amcache is an application-compatibility database — a registry hive at
//! `C:\Windows\AppCompat\Programs\Amcache.hve`. Its `Root\InventoryApplicationFile` subkeys are
//! **presence evidence** for every executable Windows inventoried: the file's path,
//! `SHA-1`, publisher, size, and link date. `Root\InventoryDevicePnp` records PnP/USB devices.
//! This crate decodes both into typed entries. It walks the hive with [`winreg_core`]; it never
//! writes, is `#![forbid(unsafe_code)]`, and handles registry reads without panicking or
//! unwrapping. Structural/raw-value read failures propagate, while an unreadable optional typed
//! value remains available as raw evidence with no decoded representation.
//!
//! Both schemas are decoded: the **modern** one (Windows 10 1607+ / Windows 11), whose entries
//! live under `Root\InventoryApplicationFile`, and the **legacy** pre-1607 layout
//! (`Root\File\{volume-GUID}\…`, numbered values, used by Windows 8/8.1 and Server 2012 R2).
//! [`Amcache::schema`] reports which was found. Legacy hives carry no `InventoryDevicePnp`, so
//! their device list is empty; modern hives populate both.
//!
//! Field semantics follow libyal's `dtformats` "AMCache.hve format" documentation and are
//! cross-validated against `regipy` and a second, independent Amcache parser (see `tests/`). The
//! `SHA-1` is emitted when the `FileId` ends in 40 valid ASCII hexadecimal characters (normally
//! the value after its leading `0000` padding).

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::io::Cursor;

use winreg_core::error::HiveError;
use winreg_core::hive::Hive;
use winreg_core::key::Key;

/// One `InventoryApplicationFile` entry — an executable Windows inventoried (presence evidence).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AmcacheFileEntry {
    /// The subkey name — a `<name>|<LongPathHash>` token uniquely keying the file.
    pub key_name: String,
    /// Full hive-relative registry key path, including the legacy volume key when applicable.
    pub source_key_path: String,
    /// Legacy parent volume key last-write time as raw Windows `FILETIME`; absent for modern rows.
    pub source_volume_key_last_written_filetime: Option<u64>,
    /// The file name (`Name`), e.g. `7z.exe`.
    pub name: Option<String>,
    /// The original file name from the executable's version information (`OriginalFileName`).
    pub original_file_name: Option<String>,
    /// The file description from the executable's version information (`Description`).
    pub description: Option<String>,
    /// The full lower-case path (`LowerCaseLongPath`).
    pub full_path: Option<String>,
    /// The Amcache path token (`LongPathHash`), normally also present after `|` in the key name.
    pub long_path_hash: Option<String>,
    /// The raw file identifier (`FileId`). On registry-backed Amcache hives this is normally
    /// `0000` followed by the SHA-1 digest.
    pub file_id: Option<String>,
    /// The file's `SHA-1` (the valid 40-hex-character suffix of `FileId`); `None` when Amcache
    /// recorded no hash or a malformed identifier (common for Store/AppX binaries).
    pub sha1: Option<String>,
    /// The file's SHA-256 (`Sha256`), when recorded by newer Windows versions.
    pub sha256: Option<String>,
    /// The associated program id (`ProgramId`), linking to an `InventoryApplication` entry.
    pub program_id: Option<String>,
    /// The publisher string recorded from file metadata (`Publisher`); this is not signature
    /// validation.
    pub publisher: Option<String>,
    /// The file version (`Version`).
    pub version: Option<String>,
    /// The binary file version (`BinFileVersion`).
    pub bin_file_version: Option<String>,
    /// The product name (`ProductName`).
    pub product_name: Option<String>,
    /// The product version (`ProductVersion`).
    pub product_version: Option<String>,
    /// The binary product version (`BinProductVersion`).
    pub bin_product_version: Option<String>,
    /// The binary type (`BinaryType`), e.g. `pe64_amd64`.
    pub binary_type: Option<String>,
    /// The executable link date exactly as Amcache recorded it (`LinkDate`).
    pub link_date: Option<String>,
    /// The full package name for a packaged/Store application (`AppxPackageFullName`).
    pub appx_package_full_name: Option<String>,
    /// The application identifier within the package (`AppxPackageRelativeId`).
    pub appx_package_relative_id: Option<String>,
    /// The file size in bytes (`Size`).
    pub size: Option<u64>,
    /// The executable language identifier (`Language`).
    pub language: Option<u32>,
    /// Whether Windows identified the entry as a PE file (`IsPeFile`).
    pub is_pe_file: Option<bool>,
    /// Whether Windows identified the entry as an operating-system component (`IsOsComponent`).
    pub is_os_component: Option<bool>,
    /// The NTFS update sequence number recorded for the file (`Usn`).
    pub usn: Option<u64>,
    /// Every value on the source registry key, retained with its type and exact raw bytes.
    pub registry_values: Vec<AmcacheRegistryValue>,
    /// The subkey's last-written time as a raw Windows `FILETIME` — when Amcache recorded the
    /// entry (a distinct timestamp from the file's own link date).
    pub key_last_written_filetime: u64,
}

/// One `InventoryDevicePnp` entry — a PnP / USB device Windows inventoried.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AmcacheDeviceEntry {
    /// The subkey name (a device-instance token).
    pub key_name: String,
    /// Full hive-relative registry key path.
    pub source_key_path: String,
    /// Human-readable description (`Description`).
    pub description: Option<String>,
    /// Bus-reported description (`BusReportedDescription`) — often the friendly device name.
    pub bus_description: Option<String>,
    /// Hardware identifiers (`HWID`). A single `REG_SZ` remains one unsplit item, while a
    /// `REG_MULTI_SZ` retains every item.
    pub hwid: Vec<String>,
    /// Compatible identifiers (`COMPID`).
    pub comp_id: Vec<String>,
    /// The manufacturer (`Manufacturer`).
    pub manufacturer: Option<String>,
    /// The model (`Model`).
    pub model: Option<String>,
    /// The device setup class (`Class`).
    pub class: Option<String>,
    /// The device setup class GUID (`ClassGuid`).
    pub class_guid: Option<String>,
    /// The device container GUID (`ContainerId`).
    pub container_id: Option<String>,
    /// Device-interface class GUIDs (`DeviceInterfaceClasses`).
    pub device_interface_classes: Vec<String>,
    /// The device state exactly as Windows recorded it (`DeviceState`).
    pub device_state: Option<String>,
    /// The Amcache driver identifier (`DriverId`).
    pub driver_id: Option<String>,
    /// The driver binary name (`DriverName`).
    pub driver_name: Option<String>,
    /// The driver package's strong name (`DriverPackageStrongName`).
    pub driver_package_strong_name: Option<String>,
    /// The driver version date exactly as Windows recorded it (`DriverVerDate`).
    pub driver_ver_date: Option<String>,
    /// The driver version (`DriverVerVersion`).
    pub driver_ver_version: Option<String>,
    /// The PnP enumerator (`Enumerator`).
    pub enumerator: Option<String>,
    /// Additional INF identifiers (`ExtendedInfs`).
    pub extended_infs: Vec<String>,
    /// The first-install date exactly as Windows recorded it (`FirstInstallDate`).
    pub first_install_date: Option<String>,
    /// The INF file name (`Inf`).
    pub inf: Option<String>,
    /// The install date exactly as Windows recorded it (`InstallDate`).
    pub install_date: Option<String>,
    /// The installation state exactly as Windows recorded it (`InstallState`).
    pub install_state: Option<String>,
    /// Device setup-class lower filters (`LowerClassFilters`).
    pub lower_class_filters: Vec<String>,
    /// Device lower filters (`LowerFilters`).
    pub lower_filters: Vec<String>,
    /// The identifier that matched the installed driver (`MatchingID`).
    pub matching_id: Option<String>,
    /// The parent device identifier (`ParentId`).
    pub parent_id: Option<String>,
    /// The PnP problem code exactly as Windows recorded it (`ProblemCode`).
    pub problem_code: Option<String>,
    /// The driver provider (`Provider`).
    pub provider: Option<String>,
    /// The device service (`Service`).
    pub service: Option<String>,
    /// Driver stack identifiers (`STACKID`).
    pub stack_id: Vec<String>,
    /// Device setup-class upper filters (`UpperClassFilters`).
    pub upper_class_filters: Vec<String>,
    /// Device upper filters (`UpperFilters`).
    pub upper_filters: Vec<String>,
    /// Physical device location paths (`LocationPaths`).
    pub location_paths: Vec<String>,
    /// Every value on the source registry key, retained with its type and exact raw bytes.
    pub registry_values: Vec<AmcacheRegistryValue>,
    /// The subkey's last-written time as a raw Windows `FILETIME`.
    pub key_last_written_filetime: u64,
}

/// A registry value retained alongside the typed Amcache schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmcacheRegistryValue {
    /// Registry value name. An empty name denotes the default value.
    pub name: String,
    /// Windows registry type name, for example `REG_SZ` or `REG_BINARY`.
    pub registry_type: String,
    /// Type-aware decoded value when a lossless scalar/list representation is available.
    pub decoded: Option<AmcacheRegistryValueData>,
    /// Exact registry data bytes encoded as lower-case hexadecimal.
    pub raw_data_hex: String,
}

/// Type-aware decoded data for an [`AmcacheRegistryValue`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AmcacheRegistryValueData {
    /// `REG_SZ`, `REG_EXPAND_SZ`, or `REG_LINK` data.
    String(String),
    /// `REG_MULTI_SZ` data, retaining every decoded item.
    MultiString(Vec<String>),
    /// `REG_DWORD` or `REG_DWORD_BIG_ENDIAN` data.
    U32(u32),
    /// `REG_QWORD` data.
    U64(u64),
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
            Self::NotAmcache => write!(
                f,
                "hive has neither Root\\InventoryApplicationFile nor Root\\File — not an Amcache hive with a supported schema"
            ),
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
        let volume_name = volume.name();
        let volume_last_written = volume.last_written_raw();
        for sk in volume.subkeys()? {
            let key_name = sk.name();
            let full_path = str_value(&sk, "15");
            let name = full_path.as_deref().map(base_name);
            let file_id = str_value(&sk, "101");
            let sha1 = file_id.as_deref().and_then(sha1_from_file_id);
            out.push(AmcacheFileEntry {
                source_key_path: format!("Root\\File\\{volume_name}\\{key_name}"),
                source_volume_key_last_written_filetime: Some(volume_last_written),
                key_name,
                name,
                full_path,
                file_id,
                sha1,
                program_id: str_value(&sk, "100"),
                publisher: str_value(&sk, "1"),
                product_name: str_value(&sk, "0"),
                registry_values: registry_values(&sk)?,
                key_last_written_filetime: sk.last_written_raw(),
                ..AmcacheFileEntry::default()
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
        let key_name = sk.name();
        let file_id = str_value(&sk, "FileId");
        let sha1 = file_id.as_deref().and_then(sha1_from_file_id);
        out.push(AmcacheFileEntry {
            source_key_path: format!("Root\\InventoryApplicationFile\\{key_name}"),
            source_volume_key_last_written_filetime: None,
            key_name,
            name: str_value(&sk, "Name"),
            original_file_name: str_value(&sk, "OriginalFileName"),
            description: str_value(&sk, "Description"),
            full_path: str_value(&sk, "LowerCaseLongPath"),
            long_path_hash: str_value(&sk, "LongPathHash"),
            file_id,
            sha1,
            sha256: str_value(&sk, "Sha256"),
            program_id: str_value(&sk, "ProgramId"),
            publisher: str_value(&sk, "Publisher"),
            version: str_value(&sk, "Version"),
            bin_file_version: str_value(&sk, "BinFileVersion"),
            product_name: str_value(&sk, "ProductName"),
            product_version: str_value(&sk, "ProductVersion"),
            bin_product_version: str_value(&sk, "BinProductVersion"),
            binary_type: str_value(&sk, "BinaryType"),
            link_date: str_value(&sk, "LinkDate"),
            appx_package_full_name: str_value(&sk, "AppxPackageFullName"),
            appx_package_relative_id: str_value(&sk, "AppxPackageRelativeId"),
            size: int_value(&sk, "Size"),
            language: int_value(&sk, "Language").and_then(|value| value.try_into().ok()),
            is_pe_file: bool_value(&sk, "IsPeFile"),
            is_os_component: bool_value(&sk, "IsOsComponent"),
            usn: int_value(&sk, "Usn"),
            registry_values: registry_values(&sk)?,
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
        let key_name = sk.name();
        out.push(AmcacheDeviceEntry {
            source_key_path: format!("Root\\InventoryDevicePnp\\{key_name}"),
            key_name,
            description: str_value(&sk, "Description"),
            bus_description: str_value(&sk, "BusReportedDescription"),
            hwid: multi_str_value(&sk, "HWID"),
            comp_id: multi_str_value(&sk, "COMPID"),
            manufacturer: str_value(&sk, "Manufacturer"),
            model: str_value(&sk, "Model"),
            class: str_value(&sk, "Class"),
            class_guid: str_value(&sk, "ClassGuid"),
            container_id: str_value(&sk, "ContainerId"),
            device_interface_classes: multi_str_value(&sk, "DeviceInterfaceClasses"),
            device_state: str_value(&sk, "DeviceState"),
            driver_id: str_value(&sk, "DriverId"),
            driver_name: str_value(&sk, "DriverName"),
            driver_package_strong_name: str_value(&sk, "DriverPackageStrongName"),
            driver_ver_date: str_value(&sk, "DriverVerDate"),
            driver_ver_version: str_value(&sk, "DriverVerVersion"),
            enumerator: str_value(&sk, "Enumerator"),
            extended_infs: multi_str_value(&sk, "ExtendedInfs"),
            first_install_date: str_value(&sk, "FirstInstallDate"),
            inf: str_value(&sk, "Inf"),
            install_date: str_value(&sk, "InstallDate"),
            install_state: str_value(&sk, "InstallState"),
            lower_class_filters: multi_str_value(&sk, "LowerClassFilters"),
            lower_filters: multi_str_value(&sk, "LowerFilters"),
            matching_id: str_value(&sk, "MatchingID"),
            parent_id: str_value(&sk, "ParentId"),
            problem_code: str_value(&sk, "ProblemCode"),
            provider: str_value(&sk, "Provider"),
            service: str_value(&sk, "Service"),
            stack_id: multi_str_value(&sk, "STACKID"),
            upper_class_filters: multi_str_value(&sk, "UpperClassFilters"),
            upper_filters: multi_str_value(&sk, "UpperFilters"),
            location_paths: multi_str_value(&sk, "LocationPaths"),
            registry_values: registry_values(&sk)?,
            key_last_written_filetime: sk.last_written_raw(),
        });
    }
    Ok(out)
}

/// Retain every source value so typed output can be verified and schema additions are not silently
/// discarded. Raw bytes are always included; common types also get a decoded representation.
fn registry_values(
    key: &Key<'_, Hive<Cursor<Vec<u8>>>>,
) -> Result<Vec<AmcacheRegistryValue>, AmcacheError> {
    let mut retained = Vec::new();
    for value in key.values()? {
        let name = value.name();
        let registry_type = value.data_type().name().to_string();
        let decoded = match registry_type.as_str() {
            "REG_SZ" | "REG_EXPAND_SZ" | "REG_LINK" => {
                value.as_string().ok().map(AmcacheRegistryValueData::String)
            }
            "REG_MULTI_SZ" => value
                .as_multi_string()
                .ok()
                .map(AmcacheRegistryValueData::MultiString),
            "REG_DWORD" => value.as_u32().ok().map(AmcacheRegistryValueData::U32),
            "REG_DWORD_BIG_ENDIAN" => value.as_u32_be().ok().map(AmcacheRegistryValueData::U32),
            "REG_QWORD" => value.as_u64().ok().map(AmcacheRegistryValueData::U64),
            _ => None,
        };
        retained.push(AmcacheRegistryValue {
            name,
            registry_type,
            decoded,
            raw_data_hex: bytes_to_hex(&value.raw_data()?),
        });
    }
    retained.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(retained)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

/// Read a value as a string, preserving whitespace and present-empty values. `None` means absent
/// or unreadable.
fn str_value(key: &Key<'_, Hive<Cursor<Vec<u8>>>>, name: &str) -> Option<String> {
    let value = key.value(name).ok()??;
    let s = value.as_string().ok()?;
    let without_terminator = s.trim_end_matches('\u{0}');
    Some(without_terminator.to_string())
}

/// Read a string or multi-string without discarding additional `REG_MULTI_SZ` items. A plain
/// `REG_SZ` is returned as a one-item vector, preserving comma-separated data as one exact value.
fn multi_str_value(key: &Key<'_, Hive<Cursor<Vec<u8>>>>, name: &str) -> Vec<String> {
    let Some(value) = key.value(name).ok().flatten() else {
        return Vec::new();
    };
    let items: Vec<String> = value
        .as_multi_string()
        .unwrap_or_default()
        .into_iter()
        .map(|item| item.trim_end_matches('\u{0}').to_string())
        .collect();
    if items.len() == 1 && items[0].is_empty() {
        Vec::new()
    } else {
        items
    }
}

/// Read an integer-valued registry flag while retaining the distinction between absent and false.
fn bool_value(key: &Key<'_, Hive<Cursor<Vec<u8>>>>, name: &str) -> Option<bool> {
    int_value(key, name).map(|value| value != 0)
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

/// The `SHA-1` encoded in a `FileId` value: Amcache normally prefixes the 40-hex-character digest
/// with `0000`. `None` when the suffix is missing, malformed, or not ASCII hexadecimal.
fn sha1_from_file_id(file_id: &str) -> Option<String> {
    let id = file_id.trim();
    let suffix = id.get(id.len().checked_sub(40)?..)?;
    suffix
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit())
        .then(|| suffix.to_ascii_lowercase())
}

#[cfg(test)]
mod tests;
