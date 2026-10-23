//! Tier-1 validation against real DFIRArtifactMuseum Amcache hives (MIT), cross-checked with
//! Eric Zimmerman's `AmcacheParser` and `regipy`. See `tests/data/README.md`.

use super::*;

const WIN10: &[u8] = include_bytes!("../tests/data/amcache_win10.hve");
const OLD_2012R2: &[u8] = include_bytes!("../tests/data/amcache_2012r2_old.hve");
/// A real but non-Amcache hive (a CFReDS NTUSER.DAT) — no `Root\InventoryApplicationFile`
/// and no `Root\File`, so it exercises the `NotAmcache` path.
const NOT_AMCACHE: &[u8] = include_bytes!("../tests/data/not_amcache.hve");

#[test]
fn win10_hive_decodes_file_and_device_entries() {
    let am = parse_bytes(WIN10).unwrap();
    // 123 InventoryApplicationFile subkeys, 189 InventoryDevicePnp (both oracles agree).
    assert_eq!(am.file_entries.len(), 123);
    assert_eq!(am.device_entries.len(), 189);
}

#[test]
fn win10_7zip_entry_matches_the_oracle() {
    let am = parse_bytes(WIN10).unwrap();
    let e = am
        .file_entries
        .iter()
        .find(|e| e.key_name.starts_with("7z.exe|"))
        .expect("7z.exe entry");
    assert_eq!(e.name.as_deref(), Some("7z.exe"));
    assert_eq!(e.original_file_name.as_deref(), Some("7z.exe"));
    assert_eq!(
        e.full_path.as_deref(),
        Some(r"c:\program files\7-zip\7z.exe")
    );
    assert_eq!(e.long_path_hash.as_deref(), Some("7z.exe|afe683e0fa522625"));
    assert_eq!(
        e.file_id.as_deref(),
        Some("00001189cebeb8ffed7316f98b895ff949a726f4026f")
    );
    // FileId 00001189… → SHA-1 last-40 (AmcacheParser + a from-FileId read agree).
    assert_eq!(
        e.sha1.as_deref(),
        Some("1189cebeb8ffed7316f98b895ff949a726f4026f")
    );
    assert_eq!(e.publisher.as_deref(), Some("igor pavlov"));
    assert_eq!(e.version.as_deref(), Some("21.07"));
    assert_eq!(e.bin_file_version.as_deref(), Some("21.7.0.0"));
    assert_eq!(e.product_name.as_deref(), Some("7-zip"));
    assert_eq!(e.product_version.as_deref(), Some("21.07"));
    assert_eq!(e.bin_product_version.as_deref(), Some("21.7.0.0"));
    assert_eq!(e.binary_type.as_deref(), Some("pe64_amd64"));
    assert_eq!(e.link_date.as_deref(), Some("12/26/2021 14:00:00"));
    assert_eq!(e.size, Some(535_040));
    assert_eq!(e.language, Some(1033));
    assert_eq!(e.usn, Some(13_667_928));
    assert_eq!(e.appx_package_full_name.as_deref(), Some(""));
    assert_eq!(e.appx_package_relative_id.as_deref(), Some(""));
    assert_eq!(
        e.source_key_path,
        format!("Root\\InventoryApplicationFile\\{}", e.key_name)
    );
    assert_eq!(e.source_volume_key_last_written_filetime, None);
    assert!(e
        .registry_values
        .iter()
        .any(|value| value.name == "Publisher"));
    // This older fixture predates these newer fields; absence remains distinct from false/empty.
    assert_eq!(e.is_pe_file, None);
    assert_eq!(e.sha256, None);
    assert!(e.key_last_written_filetime > 0);
}

#[test]
fn win10_appx_metadata_is_preserved() {
    let am = parse_bytes(WIN10).unwrap();
    let e = am
        .file_entries
        .iter()
        .find(|e| e.key_name.starts_with("3dviewer.exe|"))
        .expect("3dviewer.exe entry");
    assert_eq!(
        e.appx_package_full_name.as_deref(),
        Some("Microsoft.Microsoft3DViewer_6.1908.2042.0_x64__8wekyb3d8bbwe")
    );
    assert_eq!(
        e.appx_package_relative_id.as_deref(),
        Some("Microsoft.Microsoft3DViewer")
    );
}

#[test]
fn win10_system_binary_sha1_matches_the_oracle() {
    let am = parse_bytes(WIN10).unwrap();
    let e = am
        .file_entries
        .iter()
        .find(|e| e.name.as_deref() == Some("CompatTelRunner.exe"))
        .expect("CompatTelRunner.exe entry");
    assert_eq!(
        e.sha1.as_deref(),
        Some("77f2e744c92417653b5abd6ccb3b5e521111979a")
    );
    assert_eq!(
        e.full_path.as_deref(),
        Some(r"c:\windows\system32\compattelrunner.exe")
    );
    assert_eq!(e.is_os_component, Some(true));
}

#[test]
fn win10_device_entries_carry_a_description() {
    let am = parse_bytes(WIN10).unwrap();
    // Every device entry has a key name and a recorded write time; most carry a description.
    assert!(am.device_entries.iter().all(|d| !d.key_name.is_empty()));
    assert!(am
        .device_entries
        .iter()
        .any(|d| d.description.is_some() || d.bus_description.is_some()));
}

#[test]
fn win10_device_entry_preserves_extended_metadata_and_list_values() {
    let am = parse_bytes(WIN10).unwrap();
    let d = am
        .device_entries
        .iter()
        .find(|d| {
            d.key_name
                == "hdaudio/func_01&ven_15ad&dev_1975&subsys_15ad1975&rev_1001/5&217be3d6&0&0001"
        })
        .expect("high-definition audio device");

    assert_eq!(d.class.as_deref(), Some("media"));
    assert_eq!(
        d.class_guid.as_deref(),
        Some("{4d36e96c-e325-11ce-bfc1-08002be10318}")
    );
    assert_eq!(d.driver_name.as_deref(), Some("hdaudio.sys"));
    assert_eq!(d.driver_ver_version.as_deref(), Some("10.0.19041.264"));
    assert_eq!(d.install_date.as_deref(), Some("03-10-2022"));
    assert_eq!(d.first_install_date.as_deref(), Some("03-10-2022"));
    assert_eq!(d.provider.as_deref(), Some("Microsoft"));
    assert_eq!(d.service.as_deref(), Some("hdaudaddservice"));
    assert_eq!(d.upper_class_filters, vec!["ksthunk"]);
    assert_eq!(
        d.device_interface_classes,
        vec!["{65e8773d-8f56-11d0-a3b9-00a0c9223196}"]
    );
    // The fixture stores this as one REG_SZ containing commas. Do not split it heuristically.
    assert_eq!(d.hwid.len(), 1);
    assert!(d.hwid[0].contains(','));
    // LocationPaths is a known field absent from this older fixture.
    assert!(d.location_paths.is_empty());
}

#[test]
fn legacy_root_file_schema_decodes() {
    // The Server 2012 R2 hive uses the pre-1607 Root\File schema — 136 file entries across
    // volumes (AmcacheParser + regipy agree), no device entries.
    let am = parse_bytes(OLD_2012R2).unwrap();
    assert_eq!(am.schema, AmcacheSchema::Legacy);
    assert_eq!(am.file_entries.len(), 136);
    assert!(am.device_entries.is_empty());
    // C:\Windows\System32\vm3dservice.exe → SHA-1 (FileId 0000f0032dfb… last-40), oracle-matched.
    let e = am
        .file_entries
        .iter()
        .find(|e| e.full_path.as_deref() == Some(r"C:\Windows\System32\vm3dservice.exe"))
        .expect("vm3dservice.exe");
    assert_eq!(e.name.as_deref(), Some("vm3dservice.exe"));
    assert_eq!(
        e.file_id.as_deref(),
        Some("0000f0032dfb7e5d67dd10568e61787a4a3032ff55f5")
    );
    assert_eq!(
        e.sha1.as_deref(),
        Some("f0032dfb7e5d67dd10568e61787a4a3032ff55f5")
    );
    assert!(e.program_id.is_some());
    assert_eq!(e.sha256, None);
    assert!(e.appx_package_full_name.is_none());
    assert!(e.source_key_path.starts_with("Root\\File\\"));
    assert!(e.source_volume_key_last_written_filetime.is_some());
    assert!(e
        .registry_values
        .iter()
        .any(|value| value.name == "16" && value.registry_type == "REG_DWORD"));
    assert!(e.registry_values.iter().any(|value| value.name == "17"));
    assert!(e
        .registry_values
        .iter()
        .all(|value| !value.raw_data_hex.is_empty()));
}

#[test]
fn non_hive_bytes_error_cleanly() {
    let err = parse_bytes(b"not a hive").unwrap_err();
    assert!(matches!(err, AmcacheError::Hive(_)));
    assert!(err.to_string().contains("hive error"));
}

#[test]
fn a_non_amcache_hive_is_named_not_amcache() {
    let err = parse_bytes(NOT_AMCACHE).unwrap_err();
    assert!(matches!(err, AmcacheError::NotAmcache));
    assert!(err.to_string().contains("not an Amcache hive"));
}

#[test]
fn parse_int_le_handles_dword_qword_and_short() {
    assert_eq!(parse_int_le(&[0x00, 0x4A, 0, 0, 0, 0, 0, 0]), Some(18944)); // qword
    assert_eq!(parse_int_le(&[0x00, 0x4A, 0, 0]), Some(18944)); // dword
    assert_eq!(parse_int_le(&[1, 2]), None); // too short
}

#[test]
fn sha1_from_file_id_strips_the_leading_padding() {
    assert_eq!(
        sha1_from_file_id("00001189cebeb8ffed7316f98b895ff949a726f4026f").as_deref(),
        Some("1189cebeb8ffed7316f98b895ff949a726f4026f")
    );
    // Too short to hold a digest → None.
    assert_eq!(sha1_from_file_id("0000"), None);
    // Already 40 chars → returned as-is (lower-cased).
    assert_eq!(
        sha1_from_file_id("ABCDEF0000000000000000000000000000000000").as_deref(),
        Some("abcdef0000000000000000000000000000000000")
    );
    // Malformed registry data must neither panic nor be reported as a cryptographic hash.
    assert_eq!(
        sha1_from_file_id("0000not-a-sha1-value-xxxxxxxxxxxxxxxxxxxx"),
        None
    );
    assert_eq!(sha1_from_file_id(&format!("é{}", "a".repeat(39))), None);
}

#[test]
fn raw_registry_bytes_are_lowercase_hex() {
    assert_eq!(bytes_to_hex(&[0x00, 0x7f, 0xa5, 0xff]), "007fa5ff");
    assert!(bytes_to_hex(&[]).is_empty());
}
