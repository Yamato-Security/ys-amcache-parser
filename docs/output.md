# Output formats and schema

`ys-amcache-parser` supports human-readable text plus versioned JSON, JSON Lines, and CSV output. The
summary and findings are always present. `--files`, `--devices`, or `--all` add detailed inventory
records consistently in every format.

```console
ys-amcache-parser --all --format json  --output amcache.json  Amcache.hve
ys-amcache-parser --all --format jsonl --output amcache.jsonl Amcache.hve
ys-amcache-parser --all --format csv   --output amcache-csv   Amcache.hve
```

Text, JSON, and JSONL use standard output unless `--output` is given. Use `--output -` explicitly
for standard output. CSV requires a directory because its record types have different columns.

## JSON

One JSON document contains:

```json
{
  "output_schema_version": 1,
  "tool": { "name": "ys-amcache-parser", "version": "0.2.0" },
  "source": "Amcache.hve",
  "amcache_schema": "modern",
  "summary": {},
  "findings": [],
  "files": [],
  "devices": []
}
```

An unselected `files` or `devices` array is empty. A missing scalar registry value is `null`; a
present empty string remains `""`. List-valued fields are arrays. Raw 64-bit `FILETIME`, USN, and
file-size values are decimal strings so JavaScript consumers retain every bit. `language` remains a
number and PE/OS flags are booleans when Windows recorded them.

## JSON Lines

Each physical line is an independent JSON object with `record_type` set to `summary`, `finding`,
`file`, or `device`. Every line also carries the schema version, tool, source, and Amcache schema.
The deterministic order is summary, findings, files, then devices. Embedded newlines in evidence
are JSON-escaped and never split a record across physical lines.

```console
ys-amcache-parser --all --format jsonl Amcache.hve \
  | jq 'select(.record_type == "file" and .publisher != null)'
```

## CSV

CSV output creates or replaces four UTF-8 tables using the input hive's sanitized stem:

- `Amcache_summary.csv`
- `Amcache_findings.csv`
- `Amcache_files.csv`
- `Amcache_devices.csv`

Unselected file/device tables contain a header and no data rows. This prevents stale rows when an
output directory is reused. List-valued columns end in `_json` and contain compact JSON arrays.
CSV empty cells represent missing or recorded-empty scalar values; use JSON when that distinction
matters.

Evidence-controlled strings are written verbatim. Spreadsheet programs may treat cells beginning
with `=`, `+`, `-`, `@`, tab, or carriage return as formulas. Import all columns as text or use a
forensic-safe CSV viewer. The parser intentionally does not prefix or alter evidence values.

## File fields

File records contain:

- `key_name`, `source_key_path`, `key_last_written_utc`, `key_last_written_filetime`; legacy rows
  also carry the parent volume key's raw and formatted last-write time
- `file_id`, normalized `sha1`, and `sha256` when Windows recorded it
- `name`, `original_file_name`, `description`, `full_path`, `long_path_hash`
- `program_id`, `publisher`
- `version`, `bin_file_version`, `product_name`, `product_version`, `bin_product_version`
- `binary_type`, `link_date`, `size`, `language`, `is_pe_file`, `is_os_component`, `usn`
- `appx_package_full_name`, `appx_package_relative_id`
- `registry_values`, containing every source value with name, type, decoded value, and exact raw
  bytes as hexadecimal; this preserves future and legacy-only fields as well as typed fields

`FileId` is retained exactly. `sha1` is emitted only when its final 40 characters are valid ASCII
hexadecimal. `LinkDate` is kept in the form Windows recorded; it is not silently reinterpreted as a
timezone-aware timestamp.

## Device fields

Device records contain:

- `key_name`, `source_key_path`, `key_last_written_utc`, `key_last_written_filetime`
- `description`, `bus_description`, `manufacturer`, `model`
- `hwid`, `comp_id`, `class`, `class_guid`, `container_id`, `device_interface_classes`
- `device_state`, `problem_code`, `parent_id`, `matching_id`, `enumerator`
- `driver_id`, `driver_name`, `driver_package_strong_name`, `driver_ver_date`,
  `driver_ver_version`, `provider`, `service`, `inf`
- `install_date`, `first_install_date`, `install_state`, `extended_infs`
- `lower_class_filters`, `upper_class_filters`, `lower_filters`, `upper_filters`, `stack_id`,
  `location_paths`
- `registry_values`, containing every source registry value in type-aware and exact raw forms

`REG_MULTI_SZ` values retain every item. A comma-containing `REG_SZ` remains one value and is not
split heuristically.

## Scope and interpretation

The parser supports modern `InventoryApplicationFile` and `InventoryDevicePnp` records plus legacy
`Root\File`. It does not yet emit every other `Inventory*` branch, and it does not replay adjacent
transaction logs. Amcache supports a file-presence conclusion, not execution by itself. Publisher
is recorded file metadata, not proof of a valid Authenticode signature.
