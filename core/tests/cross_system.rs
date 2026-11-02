// Copyright (C) 2026 Shirofune Security Co., Ltd.
// Copyright (c) 2026 Albert Hui
//
// This file is changed from SecurityRonin/amcache-forensic
// (https://github.com/SecurityRonin/amcache-forensic), whose code is under the Apache License 2.0
// (LICENSE-APACHE).
//
// Unless explicitly acquired and licensed from Licensor under another license, the contents of this
// file are subject to the Reciprocal Public License ("RPL") Version 1.5, or subsequent versions as
// allowed by the RPL, and You may not copy or use this file in either source code or executable
// form, except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS" basis, WITHOUT WARRANTY
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing rights
// and limitations under the RPL.

//! Cross-system validation: parse `Amcache.hve` files from several Windows versions and confirm
//! the entry counts match the `regipy` raw subkey counts. Env-gated — point each variable at a
//! DFIRArtifactMuseum `Amcache.hve` (`Windows/Amcache/<ver>/<vm>/Amcache.hve`):
//!
//! - `AMCACHE_TEST_WIN10_RATHBUN`  → 183 file / 185 device entries
//! - `AMCACHE_TEST_WIN11_RATHBUN`  → 231 file / 187 device entries
#![allow(clippy::unwrap_used)]

fn check(env: &str, files: usize, devices: usize) {
    let Ok(path) = std::env::var(env) else {
        eprintln!("SKIP: set {env} to the corresponding Amcache.hve");
        return;
    };
    let bytes = std::fs::read(&path).unwrap();
    let am = amcache_core::parse_bytes(&bytes).unwrap();
    assert_eq!(am.file_entries.len(), files, "{env}: file entry count");
    assert_eq!(
        am.device_entries.len(),
        devices,
        "{env}: device entry count"
    );
    // Every file entry has a key name; some carry a SHA-1 and a full path.
    assert!(am.file_entries.iter().all(|e| !e.key_name.is_empty()));
    assert!(am.file_entries.iter().any(|e| e.sha1.is_some()));
}

#[test]
fn win10_rathbun_matches_regipy_counts() {
    check("AMCACHE_TEST_WIN10_RATHBUN", 183, 185);
}

#[test]
fn win11_rathbun_matches_regipy_counts() {
    check("AMCACHE_TEST_WIN11_RATHBUN", 231, 187);
}
