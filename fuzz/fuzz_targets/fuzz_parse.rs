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

//! Fuzz target: feed arbitrary bytes as an Amcache hive to the reader.
//! Invariant: `parse_bytes` never panics — malformed / non-hive input yields a typed error,
//! and hive walking is bounds-checked (no unwrap, no out-of-bounds index).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = amcache_core::parse_bytes(data);
});
