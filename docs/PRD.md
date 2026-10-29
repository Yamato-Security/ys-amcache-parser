# ys-amcache-parser — Product Requirements

*A reverse-written intent document, grounded in a same-session read of the repo
(`core/src/lib.rs`, `forensic/src/lib.rs`, `forensic/src/bin/ys-amcache-parser.rs`, the
workspace manifests, and the git history, 2026-07-24). The load-bearing decisions
live as ADRs [0001](decisions/0001-two-crate-core-forensic-split.md)–[0008](decisions/0008-cli-named-amcache4n6.md)
under `docs/decisions/`. Originally developed as part of the Security Ronin forensic
fleet; now maintained as a Yamato Security fork with the upstream history retained.*

## Executive Summary

`ys-amcache-parser` turns a Windows `Amcache.hve` hive into an inventory of every
supported executable and PnP-device record — retaining every source registry value and the
**SHA-1** when Windows recorded one — and flags a small, high-precision set of
anomalies (a system-binary name at the wrong path; presence in a staging directory). It runs on
**any supported OS** as one native CLI (`ys-amcache-parser`), needs no Windows-only libraries or
external application runtime, and never modifies the evidence. Normal builds use the target platform's
standard C runtime; fully static packaging depends on the chosen Rust target and release process.

Two crates carry it: **`amcache-core`** decodes the hive (both the modern
Windows 10/11 and legacy Windows 8/Server 2012 R2 schemas) into typed entries;
**`amcache-forensic`** adds graded findings and ships the `ys-amcache-parser` CLI. Decoding
is validated Tier-1 against real hives from four Windows systems, cross-checked with
two independent oracles (`regipy` and a second, independent Amcache parser).

## Problem & Users

Amcache is one of the highest-value DFIR artifacts for answering "what ran / was
present on this box, and what is its hash?" — but the tooling to read it well is
Windows-centric or GUI-bound, and the raw hive stores its hash in a non-obvious
encoding (a `0000`-padded SHA-1). Analysts working from a Mac or Linux workstation,
or inside an automated pipeline, need a cross-platform, scriptable reader that
emits the *correct* hash and does not crash on a corrupt or hostile hive.

Primary users:

- **DFIR / IR analysts** triaging a host: "give me the inventoried executables with
  hashes, and tell me which paths look wrong."
- **Threat hunters / malware analysts** pivoting on file hashes across intel.
- **The fleet itself** — Issen/disk4n6 consume the library to fold Amcache findings
  into a unified timeline and `forensicnomicon::report`.

## What It Does

- **Decodes both Amcache schemas**, auto-detected (ADR 0004):
  - *Modern* (Windows 10 1607+ / 11): `Root\InventoryApplicationFile` →
    `AmcacheFileEntry` (complete standard application-file metadata);
    `Root\InventoryDevicePnp` → `AmcacheDeviceEntry` (complete standard PnP metadata).
    Every source value is also retained with registry type, decoded form, and exact raw bytes.
  - *Legacy* (Windows 8/8.1 / Server 2012 R2): the pre-1607
    `Root\File\{volume-GUID}\…` numbered-value layout → `AmcacheFileEntry`
    (legacy hives carry no device inventory).
- **Emits the correct SHA-1** — the valid 40-hex-character suffix of `FileId`/`101`
  (ADR 0005), lower-cased, matching both oracles byte-for-byte.
- **Grades two high-precision anomalies** (ADR 0006):
  `AMCACHE-SYSTEM-BINARY-RELOCATED` (High, `T1036.005`) and
  `AMCACHE-SUSPICIOUS-PATH` (Medium, `T1204`), carrying the file's SHA-1 as a hash subject when
  available and phrased "consistent with …" — observations, never verdicts.
- **`ys-amcache-parser` CLI** (ADR 0008, superseded): selectors add complete file/device records to
  the always-present summary and findings. It emits human-readable text, versioned JSON, streamable JSONL, or separate
  homogeneous CSV tables.
- **Reads read-only, panic-free, on untrusted input** — `#![forbid(unsafe_code)]`,
  `unwrap_used`/`expect_used` denied, fuzzed parse + audit pipelines (ADR 0003).

## Scope

- Read and decode the modern and legacy Amcache schemas from raw hive bytes.
- Produce typed file/device entries and the correct per-file SHA-1.
- Grade the two masquerading/staging anomalies and emit them as canonical
  `forensicnomicon::report` findings.
- Ship a cross-platform, scriptable CLI and a reusable library API
  (`parse_bytes`, `analyze_bytes`, `audit`).
- Preserve known, legacy-only, and future registry metadata in versioned machine-readable output.

## Non-Goals

- **Not a general registry tool.** REGF byte-level parsing lives in `winreg-core`
  (ADR 0002); this repo owns only the Amcache schema.
- **Not a hive editor or recovery tool.** It never writes; it does not repair
  hives or replay transaction logs (validation runs the oracle with `--nl` to match
  a plain hive read).
- **Not proof of execution.** Amcache is evidence of *presence* — it also
  inventories installed and scanned files. The library and findings state this
  explicitly; correlation into an execution conclusion is Issen's/the tribunal's job.
- **Not an exhaustive classifier.** The analyzer is a high-precision triage signal
  (two codes); broad enumeration is the CLI's `--files`/`--devices` listing.
- **Not a transaction-log / `Amcache.hve.LOG*` merger** — out of scope for the current release.

## Artifact Family

Windows Application Compatibility inventory: `C:\Windows\AppCompat\Programs\Amcache.hve`
(and its legacy predecessor layout). One artifact family, hence the Pattern A
single-format `core` + `forensic` split (ADR 0001).

## Validation Approach

Tier-1 correctness against **real DFIRArtifactMuseum hives** (MIT-licensed) from
four Windows systems — Windows 10 (two VMs), Windows 11, and Server 2012 R2 (legacy
`Root\File`) — cross-checked against **two independent oracles**, `regipy` and
a second, independent Amcache parser. Both oracles agree with `amcache-core` on every
entry count, and sample hashes match byte-for-byte (`7z.exe` →
`1189cebeb8ffed7316f98b895ff949a726f4026f`). Details and fixture provenance:
[`docs/validation.md`](validation.md) and `core/tests/data/README.md`. The parse and
audit pipelines are additionally fuzzed (`fuzz/fuzz_targets/`) so hostile hives
degrade to a typed error, never a panic.
