# ys-amcache-parser

[![CI](https://github.com/Yamato-Security/ys-amcache-parser/actions/workflows/ci.yml/badge.svg)](https://github.com/Yamato-Security/ys-amcache-parser/actions/workflows/ci.yml)
[![Rust 1.99+](https://img.shields.io/badge/rust-1.99%2B-orange.svg)](https://www.rust-lang.org)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

**Establish what was present on a Windows box — with a SHA-1 to pivot on when available — straight
from `Amcache.hve`, on any OS.** A panic-free-by-construction reader for modern and legacy Amcache
schemas plus an analyzer that flags high-signal masquerading and staging-directory presence.

This project is a Yamato Security-maintained fork of
[`SecurityRonin/amcache-forensic`](https://github.com/SecurityRonin/amcache-forensic).
The complete upstream Git history and Apache-2.0 license are retained. Yamato Security's changes
add richer forensic metadata and structured output while preserving the original project's
cross-platform parser and attribution.

The command and the crates are named after the repository: the command `ys-amcache-parser`
(upstream's was `amcache4n6`), the crates `ys-amcache-parser` (upstream's `amcache-forensic`;
library `amcache_forensic`) and `ys-amcache-parser-core` (upstream's `amcache-core`; library
`amcache_core`). They are version 1.0.0, by Albert Hui and Zach Mathis (@yamatosecurity), on Rust's
2024 edition, require Rust 1.99, and are not published to crates.io.

## Run it

```console
$ git clone https://github.com/Yamato-Security/ys-amcache-parser.git
$ cd ys-amcache-parser
$ cargo build --release
$ ./target/release/ys-amcache-parser /path/to/Amcache.hve
Amcache: 123 file entries, 189 device entries
Findings (4):
  [MEDIUM] AMCACHE-SUSPICIOUS-PATH  c:\users\testuser\downloads\sysmon\sysmon64.exe
    sysmon64.exe at c:\users\testuser\downloads\sysmon\sysmon64.exe (SHA-1 71f5e906848b8e94e951551a08a4c9a045f19a03) sits in a directory commonly used to stage malware — a suspicious presence that warrants correlation with execution evidence.
  [MEDIUM] AMCACHE-SUSPICIOUS-PATH  c:\users\testuser\appdata\local\temp\…\ninite.exe
    ninite.exe … (SHA-1 ba7f0b553fe4eb017d2a2b2451f7a3e6ff2b521d) …
```

The summary and findings are always included in every format. Use `--files` or `--devices` to add
the corresponding complete records, or `--all` for both. With no selector, no detailed file or
device rows are included.

```console
# Complete, pretty-printed JSON document
$ ./target/release/ys-amcache-parser --all --format json \
    --output amcache.json /path/to/Amcache.hve

# Streamable JSON Lines, suitable for jq
$ ./target/release/ys-amcache-parser --all --format jsonl /path/to/Amcache.hve \
    | jq 'select(.record_type == "file" and .publisher != null)'

# Separate homogeneous CSV tables for summary, findings, files, and devices
$ ./target/release/ys-amcache-parser --all --format csv \
    --output amcache-csv /path/to/Amcache.hve
```

JSON and JSONL use the versioned `output_schema_version` field. CSV requires an output directory
because file, device, and finding records have different schemas; all four tables are replaced on
each run, and unselected detail tables contain only their header. List-valued registry data is a
JSON array in JSON/JSONL and a compact JSON array inside the corresponding CSV cell. Raw `FILETIME`,
USN, and size values are decimal strings so JavaScript consumers do not lose 64-bit precision. See
the [output schema documentation](docs/output.md) for every field.

> **CSV safety:** evidence strings are preserved verbatim. Spreadsheet software may interpret
> cells beginning with `=`, `+`, `-`, `@`, tab, or carriage return as formulas. Import CSV as text
> or inspect it with a forensic-safe viewer; the parser deliberately does not mutate evidence to
> make it spreadsheet-safe.

## What it decodes

Both Amcache schemas (`C:\Windows\AppCompat\Programs\Amcache.hve`); `Amcache::schema` reports which:

- **Modern (Windows 10/11)** — all standard fields from `InventoryApplicationFile`, including raw
  `FileId`, normalized **SHA-1**, SHA-256 when present, path, original name, description, publisher,
  file/product versions, binary type, size, language, link date, PE/OS flags, AppX identity, USN,
  and both formatted and raw record time. All standard `InventoryDevicePnp` fields are retained,
  including hardware/compatible IDs, class and container IDs, driver/INF/provider/service metadata,
  install dates and state, filters, interfaces, stack IDs, and location paths. Multi-string values
  retain every item. Every source registry value is also retained with its registry type, decoded
  form when available, and exact raw bytes as hexadecimal, so new and legacy-only fields survive
  schema changes.
- **Legacy (Windows 8/8.1, Server 2012 R2)** — the pre-1607 `Root\File\{volume-GUID}\…` layout with numbered values (`15`=path, `101`=SHA-1, `100`=program id, `0`=product, `1`=publisher) → `AmcacheFileEntry`. Legacy hives carry no device inventory.

The current parser supports `InventoryApplicationFile`, `InventoryDevicePnp`, and legacy
`Root\File`. Other `Inventory*` branches are outside the current output schema. It reads the hive
as supplied and does not replay adjacent transaction logs (`Amcache.hve.LOG1`/`.LOG2`).

> **Amcache is evidence of *presence*, not proof of *execution*** — it also inventories files that
> were installed or scanned. Its value is the path plus a hash to identify the file. Findings are
> observations ("consistent with …"), never verdicts.
>
> **Publisher is recorded metadata, not signature validation.** A populated Publisher field does
> not establish that the file was Authenticode-signed or that a signature was valid at collection
> time. Verify the original executable separately when trust or authenticity matters.

## Layers

- **`ys-amcache-parser-core`** (library `amcache_core`) — `parse_bytes(&[u8]) -> Amcache`. Walks the hive with [`winreg-core`], `#![forbid(unsafe_code)]`, panic-free by lint.
- **`ys-amcache-parser`** (library `amcache_forensic`) — `analyze_bytes` + `audit` (graded `forensicnomicon` findings with the
  SHA-1 as a hash subject when available) and the `ys-amcache-parser` CLI.

## Validation

Tier-1 against **real DFIRArtifactMuseum hives** (MIT) from **four Windows systems**, cross-checked with **two independent oracles** — `regipy` and a second, independent Amcache parser:

| Hive | Files | Devices |
|---|---|---|
| Win10 (APTSimulatorVM) | 123 | 189 |
| Win10 (RathbunVM) | 183 | 185 |
| Win11 (RathbunVM) | 231 | 187 |
| Server 2012 R2 (Stolen Szechuan, legacy `Root\File`) | 136 | — |

`7z.exe` → SHA-1 `1189cebeb8ffed7316f98b895ff949a726f4026f`, `CompatTelRunner.exe` → `77f2e744…` — matching both oracles byte-for-byte. See `core/tests/data/README.md`.

## Findings

| Code | Severity | MITRE | Fires when |
|---|---|---|---|
| `AMCACHE-SYSTEM-BINARY-RELOCATED` | High | T1036.005 | A Windows system-binary name recorded at a non-`System32` path (masquerading). |
| `AMCACHE-SUSPICIOUS-PATH` | Medium | T1204 | An executable inventoried from a common staging directory (Temp, Downloads, `$Recycle.Bin`, …). |

---

Originally developed by [Security Ronin](https://github.com/SecurityRonin). Modified and
maintained by [Yamato Security](https://github.com/Yamato-Security) under the Apache-2.0 license.
