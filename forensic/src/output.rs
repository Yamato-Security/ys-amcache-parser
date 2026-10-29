//! Stable human-readable and machine-readable output for [`AmcacheReport`].
//!
//! JSON and JSONL use a versioned schema. CSV is emitted as separate homogeneous tables because
//! application-file, PnP-device, and finding records do not share a useful tabular schema.

use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

use forensicnomicon::report::Observation;
use serde::Serialize;
use winreg_core::key::filetime_to_datetime;

use crate::{
    AmcacheAnomaly, AmcacheDeviceEntry, AmcacheFileEntry, AmcacheRegistryValue,
    AmcacheRegistryValueData, AmcacheReport, AmcacheSchema,
};

/// Version of the JSON, JSONL, and CSV field contract.
pub const OUTPUT_SCHEMA_VERSION: u8 = 1;

/// Selects the detailed record types included after the always-present summary and findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OutputOptions {
    /// Include application-file inventory records.
    pub files: bool,
    /// Include PnP-device inventory records.
    pub devices: bool,
}

/// A failure while serializing or writing output.
#[derive(Debug)]
pub enum OutputError {
    /// File or stream I/O failed.
    Io(io::Error),
    /// JSON serialization failed.
    Json(serde_json::Error),
    /// CSV serialization failed.
    Csv(csv::Error),
}

impl fmt::Display for OutputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "output I/O error: {error}"),
            Self::Json(error) => write!(formatter, "JSON output error: {error}"),
            Self::Csv(error) => write!(formatter, "CSV output error: {error}"),
        }
    }
}

impl std::error::Error for OutputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::Csv(error) => Some(error),
        }
    }
}

impl From<io::Error> for OutputError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for OutputError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<csv::Error> for OutputError {
    fn from(error: csv::Error) -> Self {
        Self::Csv(error)
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
struct Tool<'a> {
    name: &'a str,
    version: &'a str,
}

#[derive(Debug, Clone, Serialize)]
struct Summary {
    file_count: usize,
    device_count: usize,
    finding_count: usize,
    files_included: bool,
    devices_included: bool,
}

#[derive(Debug, Serialize)]
struct JsonReport<'a> {
    output_schema_version: u8,
    tool: Tool<'static>,
    source: &'a str,
    amcache_schema: &'static str,
    summary: Summary,
    findings: Vec<FindingRecord>,
    files: Vec<FileRecord<'a>>,
    devices: Vec<DeviceRecord<'a>>,
}

#[derive(Debug, Serialize)]
struct JsonlEnvelope<'a, T: Serialize> {
    output_schema_version: u8,
    tool: Tool<'static>,
    source: &'a str,
    amcache_schema: &'static str,
    record_type: &'static str,
    #[serde(flatten)]
    record: T,
}

#[derive(Debug, Serialize)]
struct FileRecord<'a> {
    key_name: &'a str,
    source_key_path: &'a str,
    source_volume_key_last_written_utc: Option<String>,
    /// Decimal string to retain all 64 bits in JavaScript and spreadsheet consumers.
    source_volume_key_last_written_filetime: Option<String>,
    key_last_written_utc: Option<String>,
    /// Decimal string to retain all 64 bits in JavaScript and spreadsheet consumers.
    key_last_written_filetime: String,
    file_id: Option<&'a str>,
    sha1: Option<&'a str>,
    sha256: Option<&'a str>,
    name: Option<&'a str>,
    original_file_name: Option<&'a str>,
    description: Option<&'a str>,
    full_path: Option<&'a str>,
    long_path_hash: Option<&'a str>,
    program_id: Option<&'a str>,
    publisher: Option<&'a str>,
    version: Option<&'a str>,
    bin_file_version: Option<&'a str>,
    product_name: Option<&'a str>,
    product_version: Option<&'a str>,
    bin_product_version: Option<&'a str>,
    binary_type: Option<&'a str>,
    link_date: Option<&'a str>,
    appx_package_full_name: Option<&'a str>,
    appx_package_relative_id: Option<&'a str>,
    /// Decimal string to retain all 64 bits in JavaScript and spreadsheet consumers.
    size: Option<String>,
    language: Option<u32>,
    is_pe_file: Option<bool>,
    is_os_component: Option<bool>,
    /// Decimal string to retain all 64 bits in JavaScript and spreadsheet consumers.
    usn: Option<String>,
    registry_values: Vec<RegistryValueRecord<'a>>,
}

impl<'a> From<&'a AmcacheFileEntry> for FileRecord<'a> {
    fn from(entry: &'a AmcacheFileEntry) -> Self {
        Self {
            key_name: &entry.key_name,
            source_key_path: &entry.source_key_path,
            source_volume_key_last_written_utc: entry
                .source_volume_key_last_written_filetime
                .and_then(format_filetime),
            source_volume_key_last_written_filetime: entry
                .source_volume_key_last_written_filetime
                .map(|value| value.to_string()),
            key_last_written_utc: format_filetime(entry.key_last_written_filetime),
            key_last_written_filetime: entry.key_last_written_filetime.to_string(),
            file_id: entry.file_id.as_deref(),
            sha1: entry.sha1.as_deref(),
            sha256: entry.sha256.as_deref(),
            name: entry.name.as_deref(),
            original_file_name: entry.original_file_name.as_deref(),
            description: entry.description.as_deref(),
            full_path: entry.full_path.as_deref(),
            long_path_hash: entry.long_path_hash.as_deref(),
            program_id: entry.program_id.as_deref(),
            publisher: entry.publisher.as_deref(),
            version: entry.version.as_deref(),
            bin_file_version: entry.bin_file_version.as_deref(),
            product_name: entry.product_name.as_deref(),
            product_version: entry.product_version.as_deref(),
            bin_product_version: entry.bin_product_version.as_deref(),
            binary_type: entry.binary_type.as_deref(),
            link_date: entry.link_date.as_deref(),
            appx_package_full_name: entry.appx_package_full_name.as_deref(),
            appx_package_relative_id: entry.appx_package_relative_id.as_deref(),
            size: entry.size.map(|value| value.to_string()),
            language: entry.language,
            is_pe_file: entry.is_pe_file,
            is_os_component: entry.is_os_component,
            usn: entry.usn.map(|value| value.to_string()),
            registry_values: entry
                .registry_values
                .iter()
                .map(RegistryValueRecord::from)
                .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
struct DeviceRecord<'a> {
    key_name: &'a str,
    source_key_path: &'a str,
    key_last_written_utc: Option<String>,
    /// Decimal string to retain all 64 bits in JavaScript and spreadsheet consumers.
    key_last_written_filetime: String,
    description: Option<&'a str>,
    bus_description: Option<&'a str>,
    hwid: &'a [String],
    comp_id: &'a [String],
    manufacturer: Option<&'a str>,
    model: Option<&'a str>,
    class: Option<&'a str>,
    class_guid: Option<&'a str>,
    container_id: Option<&'a str>,
    device_interface_classes: &'a [String],
    device_state: Option<&'a str>,
    driver_id: Option<&'a str>,
    driver_name: Option<&'a str>,
    driver_package_strong_name: Option<&'a str>,
    driver_ver_date: Option<&'a str>,
    driver_ver_version: Option<&'a str>,
    enumerator: Option<&'a str>,
    extended_infs: &'a [String],
    first_install_date: Option<&'a str>,
    inf: Option<&'a str>,
    install_date: Option<&'a str>,
    install_state: Option<&'a str>,
    lower_class_filters: &'a [String],
    lower_filters: &'a [String],
    matching_id: Option<&'a str>,
    parent_id: Option<&'a str>,
    problem_code: Option<&'a str>,
    provider: Option<&'a str>,
    service: Option<&'a str>,
    stack_id: &'a [String],
    upper_class_filters: &'a [String],
    upper_filters: &'a [String],
    location_paths: &'a [String],
    registry_values: Vec<RegistryValueRecord<'a>>,
}

impl<'a> From<&'a AmcacheDeviceEntry> for DeviceRecord<'a> {
    fn from(entry: &'a AmcacheDeviceEntry) -> Self {
        Self {
            key_name: &entry.key_name,
            source_key_path: &entry.source_key_path,
            key_last_written_utc: format_filetime(entry.key_last_written_filetime),
            key_last_written_filetime: entry.key_last_written_filetime.to_string(),
            description: entry.description.as_deref(),
            bus_description: entry.bus_description.as_deref(),
            hwid: &entry.hwid,
            comp_id: &entry.comp_id,
            manufacturer: entry.manufacturer.as_deref(),
            model: entry.model.as_deref(),
            class: entry.class.as_deref(),
            class_guid: entry.class_guid.as_deref(),
            container_id: entry.container_id.as_deref(),
            device_interface_classes: &entry.device_interface_classes,
            device_state: entry.device_state.as_deref(),
            driver_id: entry.driver_id.as_deref(),
            driver_name: entry.driver_name.as_deref(),
            driver_package_strong_name: entry.driver_package_strong_name.as_deref(),
            driver_ver_date: entry.driver_ver_date.as_deref(),
            driver_ver_version: entry.driver_ver_version.as_deref(),
            enumerator: entry.enumerator.as_deref(),
            extended_infs: &entry.extended_infs,
            first_install_date: entry.first_install_date.as_deref(),
            inf: entry.inf.as_deref(),
            install_date: entry.install_date.as_deref(),
            install_state: entry.install_state.as_deref(),
            lower_class_filters: &entry.lower_class_filters,
            lower_filters: &entry.lower_filters,
            matching_id: entry.matching_id.as_deref(),
            parent_id: entry.parent_id.as_deref(),
            problem_code: entry.problem_code.as_deref(),
            provider: entry.provider.as_deref(),
            service: entry.service.as_deref(),
            stack_id: &entry.stack_id,
            upper_class_filters: &entry.upper_class_filters,
            upper_filters: &entry.upper_filters,
            location_paths: &entry.location_paths,
            registry_values: entry
                .registry_values
                .iter()
                .map(RegistryValueRecord::from)
                .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
struct RegistryValueRecord<'a> {
    name: &'a str,
    registry_type: &'a str,
    decoded: Option<RegistryDecoded<'a>>,
    raw_data_hex: &'a str,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum RegistryDecoded<'a> {
    String(&'a str),
    MultiString(&'a [String]),
    U32(u32),
    /// Decimal string to retain all 64 bits in JavaScript consumers.
    U64(String),
}

impl<'a> From<&'a AmcacheRegistryValue> for RegistryValueRecord<'a> {
    fn from(value: &'a AmcacheRegistryValue) -> Self {
        let decoded = value.decoded.as_ref().map(|decoded| match decoded {
            AmcacheRegistryValueData::String(string) => RegistryDecoded::String(string),
            AmcacheRegistryValueData::MultiString(strings) => RegistryDecoded::MultiString(strings),
            AmcacheRegistryValueData::U32(number) => RegistryDecoded::U32(*number),
            AmcacheRegistryValueData::U64(number) => RegistryDecoded::U64(number.to_string()),
        });
        Self {
            name: &value.name,
            registry_type: &value.registry_type,
            decoded,
            raw_data_hex: &value.raw_data_hex,
        }
    }
}

#[derive(Debug, Serialize)]
struct FindingRecord {
    variant: &'static str,
    code: &'static str,
    severity: String,
    category: String,
    mitre_tags: &'static [&'static str],
    name: String,
    path: String,
    sha1: Option<String>,
    note: String,
    subjects: Vec<SubjectRecord>,
}

#[derive(Debug, Serialize)]
struct SubjectRecord {
    scheme: String,
    kind: String,
    id: String,
    label: Option<String>,
}

impl From<&AmcacheAnomaly> for FindingRecord {
    fn from(anomaly: &AmcacheAnomaly) -> Self {
        let (variant, name, path, sha1) = match anomaly {
            AmcacheAnomaly::SystemBinaryRelocated { name, path, sha1 } => (
                "system_binary_relocated",
                name.clone(),
                path.clone(),
                sha1.clone(),
            ),
            AmcacheAnomaly::SuspiciousPath { name, path, sha1 } => {
                ("suspicious_path", name.clone(), path.clone(), sha1.clone())
            }
        };
        let severity = anomaly.severity().map_or_else(
            || "info".to_string(),
            |value| format!("{value:?}").to_lowercase(),
        );
        let subjects = anomaly
            .subjects()
            .into_iter()
            .map(|subject| SubjectRecord {
                scheme: subject.scheme,
                kind: subject.kind,
                id: subject.id,
                label: subject.label,
            })
            .collect();
        Self {
            variant,
            code: anomaly.code(),
            severity,
            category: format!("{:?}", anomaly.category()).to_lowercase(),
            mitre_tags: anomaly.mitre(),
            name,
            path,
            sha1,
            note: anomaly.note(),
            subjects,
        }
    }
}

/// Write the compatible human-readable report. Detailed records are included only when selected.
pub fn write_text(
    mut writer: impl Write,
    report: &AmcacheReport,
    options: OutputOptions,
) -> Result<(), OutputError> {
    writeln!(
        writer,
        "Amcache: {} file entries, {} device entries",
        report.amcache.file_entries.len(),
        report.amcache.device_entries.len()
    )?;

    if report.anomalies.is_empty() {
        writeln!(writer, "Findings: none")?;
    } else {
        writeln!(writer, "Findings ({}):", report.anomalies.len())?;
        for anomaly in &report.anomalies {
            let record = FindingRecord::from(anomaly);
            writeln!(
                writer,
                "  [{}] {}  {}",
                record.severity.to_uppercase(),
                record.code,
                record.path
            )?;
            writeln!(writer, "    {}", record.note)?;
        }
    }

    if options.files {
        writeln!(writer, "\nInventoried executables:")?;
        for entry in &report.amcache.file_entries {
            write_file_text(&mut writer, entry)?;
        }
    }
    if options.devices {
        writeln!(writer, "\nInventoried devices:")?;
        for entry in &report.amcache.device_entries {
            write_device_text(&mut writer, entry)?;
        }
    }
    Ok(())
}

/// Write one versioned, pretty-printed JSON document.
pub fn write_json(
    mut writer: impl Write,
    source: &str,
    report: &AmcacheReport,
    options: OutputOptions,
) -> Result<(), OutputError> {
    let document = json_report(source, report, options);
    serde_json::to_writer_pretty(&mut writer, &document)?;
    writeln!(writer)?;
    Ok(())
}

/// Write versioned newline-delimited JSON in summary, finding, file, device order.
pub fn write_jsonl(
    mut writer: impl Write,
    source: &str,
    report: &AmcacheReport,
    options: OutputOptions,
) -> Result<(), OutputError> {
    let schema = schema_name(report.amcache.schema);
    write_jsonl_record(
        &mut writer,
        &JsonlEnvelope {
            output_schema_version: OUTPUT_SCHEMA_VERSION,
            tool: tool(),
            source,
            amcache_schema: schema,
            record_type: "summary",
            record: summary(report, options),
        },
    )?;
    for anomaly in &report.anomalies {
        write_jsonl_record(
            &mut writer,
            &JsonlEnvelope {
                output_schema_version: OUTPUT_SCHEMA_VERSION,
                tool: tool(),
                source,
                amcache_schema: schema,
                record_type: "finding",
                record: FindingRecord::from(anomaly),
            },
        )?;
    }
    if options.files {
        for entry in &report.amcache.file_entries {
            write_jsonl_record(
                &mut writer,
                &JsonlEnvelope {
                    output_schema_version: OUTPUT_SCHEMA_VERSION,
                    tool: tool(),
                    source,
                    amcache_schema: schema,
                    record_type: "file",
                    record: FileRecord::from(entry),
                },
            )?;
        }
    }
    if options.devices {
        for entry in &report.amcache.device_entries {
            write_jsonl_record(
                &mut writer,
                &JsonlEnvelope {
                    output_schema_version: OUTPUT_SCHEMA_VERSION,
                    tool: tool(),
                    source,
                    amcache_schema: schema,
                    record_type: "device",
                    record: DeviceRecord::from(entry),
                },
            )?;
        }
    }
    Ok(())
}

/// Write homogeneous CSV tables into `directory` and return every path written.
///
/// All four tables are emitted. File/device tables contain only a header when their selector is
/// off, preventing stale evidence rows when a directory is reused. Existing files with the same
/// deterministic names are replaced.
pub fn write_csv_directory(
    directory: &Path,
    source: &str,
    report: &AmcacheReport,
    options: OutputOptions,
) -> Result<Vec<PathBuf>, OutputError> {
    fs::create_dir_all(directory)?;
    let stem = safe_stem(source);
    let schema = schema_name(report.amcache.schema);
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let staging = directory.join(format!(".{stem}.staging-{}-{suffix}", std::process::id()));
    fs::create_dir(&staging)?;

    let summary_name = format!("{stem}_summary.csv");
    let findings_name = format!("{stem}_findings.csv");
    let files_name = format!("{stem}_files.csv");
    let devices_name = format!("{stem}_devices.csv");

    // Always replace both detail tables. When a selector is off, its table has a header and no
    // rows; this prevents stale rows surviving when an output directory is reused.
    let files = if options.files {
        report.amcache.file_entries.as_slice()
    } else {
        &[]
    };
    let devices = if options.devices {
        report.amcache.device_entries.as_slice()
    } else {
        &[]
    };

    // Fully serialize every table before replacing any prior output. A disk-full or serialization
    // error therefore leaves the previous coherent set untouched.
    let staged_result = (|| -> Result<(), OutputError> {
        write_summary_csv(
            &staging.join(&summary_name),
            source,
            schema,
            report,
            options,
        )?;
        write_findings_csv(&staging.join(&findings_name), source, report)?;
        write_files_csv(&staging.join(&files_name), source, schema, files)?;
        write_devices_csv(&staging.join(&devices_name), source, schema, devices)?;
        Ok(())
    })();
    if let Err(error) = staged_result {
        let _cleanup_result = fs::remove_dir_all(&staging);
        return Err(error);
    }

    // Commit the summary last: its presence then indicates that all detail tables were staged.
    for name in [&files_name, &devices_name, &findings_name, &summary_name] {
        if let Err(error) = replace_file(&staging.join(name), &directory.join(name)) {
            let _cleanup_result = fs::remove_dir_all(&staging);
            return Err(OutputError::Io(error));
        }
    }
    fs::remove_dir(&staging)?;

    Ok(vec![
        directory.join(summary_name),
        directory.join(findings_name),
        directory.join(files_name),
        directory.join(devices_name),
    ])
}

fn replace_file(staged: &Path, destination: &Path) -> io::Result<()> {
    #[cfg(windows)]
    if destination.exists() {
        fs::remove_file(destination)?;
    }
    fs::rename(staged, destination)
}

fn json_report<'a>(
    source: &'a str,
    report: &'a AmcacheReport,
    options: OutputOptions,
) -> JsonReport<'a> {
    JsonReport {
        output_schema_version: OUTPUT_SCHEMA_VERSION,
        tool: tool(),
        source,
        amcache_schema: schema_name(report.amcache.schema),
        summary: summary(report, options),
        findings: report.anomalies.iter().map(FindingRecord::from).collect(),
        files: if options.files {
            report
                .amcache
                .file_entries
                .iter()
                .map(FileRecord::from)
                .collect()
        } else {
            Vec::new()
        },
        devices: if options.devices {
            report
                .amcache
                .device_entries
                .iter()
                .map(DeviceRecord::from)
                .collect()
        } else {
            Vec::new()
        },
    }
}

const fn tool() -> Tool<'static> {
    Tool {
        name: "ys-amcache-parser",
        version: env!("CARGO_PKG_VERSION"),
    }
}

fn summary(report: &AmcacheReport, options: OutputOptions) -> Summary {
    Summary {
        file_count: report.amcache.file_entries.len(),
        device_count: report.amcache.device_entries.len(),
        finding_count: report.anomalies.len(),
        files_included: options.files,
        devices_included: options.devices,
    }
}

const fn schema_name(schema: AmcacheSchema) -> &'static str {
    match schema {
        AmcacheSchema::Modern => "modern",
        AmcacheSchema::Legacy => "legacy",
    }
}

fn format_filetime(raw: u64) -> Option<String> {
    filetime_to_datetime(raw).map(|timestamp| timestamp.to_string())
}

fn write_jsonl_record(writer: &mut impl Write, value: &impl Serialize) -> Result<(), OutputError> {
    serde_json::to_writer(&mut *writer, value)?;
    writer.write_all(b"\n")?;
    Ok(())
}

fn write_file_text(writer: &mut impl Write, entry: &AmcacheFileEntry) -> io::Result<()> {
    writeln!(writer, "  - key_name: {}", entry.key_name)?;
    writeln!(writer, "    source_key_path: {}", entry.source_key_path)?;
    text_optional(
        writer,
        "source_volume_key_last_written_utc",
        entry
            .source_volume_key_last_written_filetime
            .and_then(format_filetime)
            .as_deref(),
    )?;
    text_display(
        writer,
        "source_volume_key_last_written_filetime",
        entry.source_volume_key_last_written_filetime,
    )?;
    text_optional(
        writer,
        "key_last_written_utc",
        format_filetime(entry.key_last_written_filetime).as_deref(),
    )?;
    writeln!(
        writer,
        "    key_last_written_filetime: {}",
        entry.key_last_written_filetime
    )?;
    text_optional(writer, "file_id", entry.file_id.as_deref())?;
    text_optional(writer, "sha1", entry.sha1.as_deref())?;
    text_optional(writer, "sha256", entry.sha256.as_deref())?;
    text_optional(writer, "name", entry.name.as_deref())?;
    text_optional(
        writer,
        "original_file_name",
        entry.original_file_name.as_deref(),
    )?;
    text_optional(writer, "description", entry.description.as_deref())?;
    text_optional(writer, "full_path", entry.full_path.as_deref())?;
    text_optional(writer, "long_path_hash", entry.long_path_hash.as_deref())?;
    text_optional(writer, "program_id", entry.program_id.as_deref())?;
    text_optional(writer, "publisher", entry.publisher.as_deref())?;
    text_optional(writer, "version", entry.version.as_deref())?;
    text_optional(
        writer,
        "bin_file_version",
        entry.bin_file_version.as_deref(),
    )?;
    text_optional(writer, "product_name", entry.product_name.as_deref())?;
    text_optional(writer, "product_version", entry.product_version.as_deref())?;
    text_optional(
        writer,
        "bin_product_version",
        entry.bin_product_version.as_deref(),
    )?;
    text_optional(writer, "binary_type", entry.binary_type.as_deref())?;
    text_optional(writer, "link_date", entry.link_date.as_deref())?;
    text_optional(
        writer,
        "appx_package_full_name",
        entry.appx_package_full_name.as_deref(),
    )?;
    text_optional(
        writer,
        "appx_package_relative_id",
        entry.appx_package_relative_id.as_deref(),
    )?;
    text_display(writer, "size", entry.size)?;
    text_display(writer, "language", entry.language)?;
    text_display(writer, "is_pe_file", entry.is_pe_file)?;
    text_display(writer, "is_os_component", entry.is_os_component)?;
    text_display(writer, "usn", entry.usn)?;
    text_registry_values(writer, &entry.registry_values)?;
    Ok(())
}

fn write_device_text(writer: &mut impl Write, entry: &AmcacheDeviceEntry) -> io::Result<()> {
    writeln!(writer, "  - key_name: {}", entry.key_name)?;
    writeln!(writer, "    source_key_path: {}", entry.source_key_path)?;
    text_optional(
        writer,
        "key_last_written_utc",
        format_filetime(entry.key_last_written_filetime).as_deref(),
    )?;
    writeln!(
        writer,
        "    key_last_written_filetime: {}",
        entry.key_last_written_filetime
    )?;
    text_optional(writer, "description", entry.description.as_deref())?;
    text_optional(writer, "bus_description", entry.bus_description.as_deref())?;
    text_list(writer, "hwid", &entry.hwid)?;
    text_list(writer, "comp_id", &entry.comp_id)?;
    text_optional(writer, "manufacturer", entry.manufacturer.as_deref())?;
    text_optional(writer, "model", entry.model.as_deref())?;
    text_optional(writer, "class", entry.class.as_deref())?;
    text_optional(writer, "class_guid", entry.class_guid.as_deref())?;
    text_optional(writer, "container_id", entry.container_id.as_deref())?;
    text_list(
        writer,
        "device_interface_classes",
        &entry.device_interface_classes,
    )?;
    text_optional(writer, "device_state", entry.device_state.as_deref())?;
    text_optional(writer, "driver_id", entry.driver_id.as_deref())?;
    text_optional(writer, "driver_name", entry.driver_name.as_deref())?;
    text_optional(
        writer,
        "driver_package_strong_name",
        entry.driver_package_strong_name.as_deref(),
    )?;
    text_optional(writer, "driver_ver_date", entry.driver_ver_date.as_deref())?;
    text_optional(
        writer,
        "driver_ver_version",
        entry.driver_ver_version.as_deref(),
    )?;
    text_optional(writer, "enumerator", entry.enumerator.as_deref())?;
    text_list(writer, "extended_infs", &entry.extended_infs)?;
    text_optional(
        writer,
        "first_install_date",
        entry.first_install_date.as_deref(),
    )?;
    text_optional(writer, "inf", entry.inf.as_deref())?;
    text_optional(writer, "install_date", entry.install_date.as_deref())?;
    text_optional(writer, "install_state", entry.install_state.as_deref())?;
    text_list(writer, "lower_class_filters", &entry.lower_class_filters)?;
    text_list(writer, "lower_filters", &entry.lower_filters)?;
    text_optional(writer, "matching_id", entry.matching_id.as_deref())?;
    text_optional(writer, "parent_id", entry.parent_id.as_deref())?;
    text_optional(writer, "problem_code", entry.problem_code.as_deref())?;
    text_optional(writer, "provider", entry.provider.as_deref())?;
    text_optional(writer, "service", entry.service.as_deref())?;
    text_list(writer, "stack_id", &entry.stack_id)?;
    text_list(writer, "upper_class_filters", &entry.upper_class_filters)?;
    text_list(writer, "upper_filters", &entry.upper_filters)?;
    text_list(writer, "location_paths", &entry.location_paths)?;
    text_registry_values(writer, &entry.registry_values)?;
    Ok(())
}

fn text_registry_values(
    writer: &mut impl Write,
    values: &[AmcacheRegistryValue],
) -> io::Result<()> {
    for value in values {
        writeln!(
            writer,
            "    registry_value[{}]: type={} decoded={:?} raw_data_hex={}",
            value.name, value.registry_type, value.decoded, value.raw_data_hex
        )?;
    }
    Ok(())
}

fn text_optional(writer: &mut impl Write, label: &str, value: Option<&str>) -> io::Result<()> {
    if let Some(value) = value {
        writeln!(writer, "    {label}: {value}")?;
    }
    Ok(())
}

fn text_display(
    writer: &mut impl Write,
    label: &str,
    value: Option<impl fmt::Display>,
) -> io::Result<()> {
    if let Some(value) = value {
        writeln!(writer, "    {label}: {value}")?;
    }
    Ok(())
}

fn text_list(writer: &mut impl Write, label: &str, values: &[String]) -> io::Result<()> {
    if !values.is_empty() {
        let json = serde_json::to_string(values).unwrap_or_else(|_| "[]".to_string());
        writeln!(writer, "    {label}: {json}")?;
    }
    Ok(())
}

fn safe_stem(source: &str) -> String {
    let name = source
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("amcache")
        .rsplit_once('.')
        .map_or_else(
            || source.rsplit(['/', '\\']).next().unwrap_or("amcache"),
            |(stem, _)| stem,
        );
    let sanitized: String = name
        .chars()
        .map(|character| {
            if character.is_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect();
    if sanitized.is_empty() {
        "amcache".to_string()
    } else {
        sanitized
    }
}

fn csv_writer(path: &Path) -> Result<csv::Writer<BufWriter<File>>, OutputError> {
    Ok(csv::WriterBuilder::new()
        .has_headers(false)
        .from_writer(BufWriter::new(File::create(path)?)))
}

fn write_summary_csv(
    path: &Path,
    source: &str,
    schema: &str,
    report: &AmcacheReport,
    options: OutputOptions,
) -> Result<(), OutputError> {
    let mut writer = csv_writer(path)?;
    writer.write_record([
        "record_type",
        "output_schema_version",
        "tool_name",
        "tool_version",
        "source",
        "amcache_schema",
        "file_count",
        "device_count",
        "finding_count",
        "files_included",
        "devices_included",
    ])?;
    writer.write_record([
        "summary".to_string(),
        OUTPUT_SCHEMA_VERSION.to_string(),
        tool().name.to_string(),
        tool().version.to_string(),
        source.to_string(),
        schema.to_string(),
        report.amcache.file_entries.len().to_string(),
        report.amcache.device_entries.len().to_string(),
        report.anomalies.len().to_string(),
        options.files.to_string(),
        options.devices.to_string(),
    ])?;
    writer.flush()?;
    Ok(())
}

fn write_findings_csv(
    path: &Path,
    source: &str,
    report: &AmcacheReport,
) -> Result<(), OutputError> {
    let mut writer = csv_writer(path)?;
    writer.write_record([
        "record_type",
        "source",
        "variant",
        "code",
        "severity",
        "category",
        "mitre_tags_json",
        "name",
        "path",
        "sha1",
        "note",
        "subjects_json",
    ])?;
    for anomaly in &report.anomalies {
        let record = FindingRecord::from(anomaly);
        writer.write_record([
            "finding".to_string(),
            source.to_string(),
            record.variant.to_string(),
            record.code.to_string(),
            record.severity,
            record.category,
            serde_json::to_string(record.mitre_tags)?,
            record.name,
            record.path,
            record.sha1.unwrap_or_default(),
            record.note,
            serde_json::to_string(&record.subjects)?,
        ])?;
    }
    writer.flush()?;
    Ok(())
}

fn write_files_csv(
    path: &Path,
    source: &str,
    schema: &str,
    entries: &[AmcacheFileEntry],
) -> Result<(), OutputError> {
    let mut writer = csv_writer(path)?;
    writer.write_record([
        "record_type",
        "source",
        "amcache_schema",
        "key_name",
        "source_key_path",
        "source_volume_key_last_written_utc",
        "source_volume_key_last_written_filetime",
        "key_last_written_utc",
        "key_last_written_filetime",
        "file_id",
        "sha1",
        "sha256",
        "name",
        "original_file_name",
        "description",
        "full_path",
        "long_path_hash",
        "program_id",
        "publisher",
        "version",
        "bin_file_version",
        "product_name",
        "product_version",
        "bin_product_version",
        "binary_type",
        "link_date",
        "appx_package_full_name",
        "appx_package_relative_id",
        "size",
        "language",
        "is_pe_file",
        "is_os_component",
        "usn",
        "registry_values_json",
    ])?;
    for entry in entries {
        let record = FileRecord::from(entry);
        let registry_values = serde_json::to_string(&record.registry_values)?;
        writer.write_record([
            "file".to_string(),
            source.to_string(),
            schema.to_string(),
            record.key_name.to_string(),
            record.source_key_path.to_string(),
            record
                .source_volume_key_last_written_utc
                .unwrap_or_default(),
            record
                .source_volume_key_last_written_filetime
                .unwrap_or_default(),
            record.key_last_written_utc.unwrap_or_default(),
            record.key_last_written_filetime,
            optional(record.file_id),
            optional(record.sha1),
            optional(record.sha256),
            optional(record.name),
            optional(record.original_file_name),
            optional(record.description),
            optional(record.full_path),
            optional(record.long_path_hash),
            optional(record.program_id),
            optional(record.publisher),
            optional(record.version),
            optional(record.bin_file_version),
            optional(record.product_name),
            optional(record.product_version),
            optional(record.bin_product_version),
            optional(record.binary_type),
            optional(record.link_date),
            optional(record.appx_package_full_name),
            optional(record.appx_package_relative_id),
            record.size.unwrap_or_default(),
            display_optional(record.language),
            display_optional(record.is_pe_file),
            display_optional(record.is_os_component),
            record.usn.unwrap_or_default(),
            registry_values,
        ])?;
    }
    writer.flush()?;
    Ok(())
}

fn write_devices_csv(
    path: &Path,
    source: &str,
    schema: &str,
    entries: &[AmcacheDeviceEntry],
) -> Result<(), OutputError> {
    let mut writer = csv_writer(path)?;
    writer.write_record([
        "record_type",
        "source",
        "amcache_schema",
        "key_name",
        "source_key_path",
        "key_last_written_utc",
        "key_last_written_filetime",
        "description",
        "bus_description",
        "hwid_json",
        "comp_id_json",
        "manufacturer",
        "model",
        "class",
        "class_guid",
        "container_id",
        "device_interface_classes_json",
        "device_state",
        "driver_id",
        "driver_name",
        "driver_package_strong_name",
        "driver_ver_date",
        "driver_ver_version",
        "enumerator",
        "extended_infs_json",
        "first_install_date",
        "inf",
        "install_date",
        "install_state",
        "lower_class_filters_json",
        "lower_filters_json",
        "matching_id",
        "parent_id",
        "problem_code",
        "provider",
        "service",
        "stack_id_json",
        "upper_class_filters_json",
        "upper_filters_json",
        "location_paths_json",
        "registry_values_json",
    ])?;
    for entry in entries {
        let record = DeviceRecord::from(entry);
        let registry_values = serde_json::to_string(&record.registry_values)?;
        writer.write_record([
            "device".to_string(),
            source.to_string(),
            schema.to_string(),
            record.key_name.to_string(),
            record.source_key_path.to_string(),
            record.key_last_written_utc.unwrap_or_default(),
            record.key_last_written_filetime,
            optional(record.description),
            optional(record.bus_description),
            serde_json::to_string(record.hwid)?,
            serde_json::to_string(record.comp_id)?,
            optional(record.manufacturer),
            optional(record.model),
            optional(record.class),
            optional(record.class_guid),
            optional(record.container_id),
            serde_json::to_string(record.device_interface_classes)?,
            optional(record.device_state),
            optional(record.driver_id),
            optional(record.driver_name),
            optional(record.driver_package_strong_name),
            optional(record.driver_ver_date),
            optional(record.driver_ver_version),
            optional(record.enumerator),
            serde_json::to_string(record.extended_infs)?,
            optional(record.first_install_date),
            optional(record.inf),
            optional(record.install_date),
            optional(record.install_state),
            serde_json::to_string(record.lower_class_filters)?,
            serde_json::to_string(record.lower_filters)?,
            optional(record.matching_id),
            optional(record.parent_id),
            optional(record.problem_code),
            optional(record.provider),
            optional(record.service),
            serde_json::to_string(record.stack_id)?,
            serde_json::to_string(record.upper_class_filters)?,
            serde_json::to_string(record.upper_filters)?,
            serde_json::to_string(record.location_paths)?,
            registry_values,
        ])?;
    }
    writer.flush()?;
    Ok(())
}

fn optional(value: Option<&str>) -> String {
    value.unwrap_or_default().to_string()
}

fn display_optional(value: Option<impl fmt::Display>) -> String {
    value.map_or_else(String::new, |value| value.to_string())
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::Amcache;

    fn report() -> AmcacheReport {
        let file = AmcacheFileEntry {
            key_name: "evil.exe|abc".to_string(),
            source_key_path: "Root\\InventoryApplicationFile\\evil.exe|abc".to_string(),
            name: Some("Evil, \"Quoted\".exe".to_string()),
            original_file_name: Some("evil.exe".to_string()),
            description: Some("line one\nline two".to_string()),
            full_path: Some(r#"c:\Users\日本\Downloads\Evil, "Quoted".exe"#.to_string()),
            file_id: Some("00000123456789012345678901234567890123456789".to_string()),
            sha1: Some("0123456789012345678901234567890123456789".to_string()),
            publisher: Some("ACME \"Security\", Inc.".to_string()),
            size: Some(u64::MAX),
            language: Some(1033),
            is_pe_file: Some(true),
            is_os_component: Some(false),
            usn: Some(u64::MAX),
            registry_values: vec![AmcacheRegistryValue {
                name: "FutureField".to_string(),
                registry_type: "REG_QWORD".to_string(),
                decoded: Some(AmcacheRegistryValueData::U64(u64::MAX)),
                raw_data_hex: "ffffffffffffffff".to_string(),
            }],
            key_last_written_filetime: 116_444_736_000_000_000,
            ..AmcacheFileEntry::default()
        };
        let device = AmcacheDeviceEntry {
            key_name: "USB/VID_1234&PID_5678".to_string(),
            source_key_path: "Root\\InventoryDevicePnp\\USB/VID_1234&PID_5678".to_string(),
            description: Some("USB, \"Forensic\"\nDevice".to_string()),
            hwid: vec!["USB\\VID_1234".to_string(), "USB\\CLASS_FF".to_string()],
            provider: Some("ACME".to_string()),
            key_last_written_filetime: 116_444_736_000_000_000,
            ..AmcacheDeviceEntry::default()
        };
        AmcacheReport {
            amcache: Amcache {
                file_entries: vec![file],
                device_entries: vec![device],
                ..Amcache::default()
            },
            anomalies: Vec::new(),
        }
    }

    #[test]
    fn json_preserves_types_nulls_and_large_integer_strings() {
        let mut output = Vec::new();
        write_json(
            &mut output,
            "Amcache.hve",
            &report(),
            OutputOptions {
                files: true,
                devices: true,
            },
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(value["output_schema_version"], 1);
        assert_eq!(value["files"][0]["publisher"], "ACME \"Security\", Inc.");
        assert_eq!(value["files"][0]["usn"], u64::MAX.to_string());
        assert_eq!(value["files"][0]["size"], u64::MAX.to_string());
        assert_eq!(
            value["files"][0]["registry_values"][0]["decoded"],
            u64::MAX.to_string()
        );
        assert_eq!(
            value["files"][0]["registry_values"][0]["raw_data_hex"],
            "ffffffffffffffff"
        );
        assert!(value["files"][0]["sha256"].is_null());
        assert_eq!(value["devices"][0]["hwid"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn jsonl_has_one_parseable_object_per_physical_line() {
        let mut output = Vec::new();
        write_jsonl(
            &mut output,
            "Amcache.hve",
            &report(),
            OutputOptions {
                files: true,
                devices: true,
            },
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();
        let rows: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0]["record_type"], "summary");
        assert_eq!(rows[1]["record_type"], "file");
        assert_eq!(rows[2]["record_type"], "device");
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn structured_findings_include_detection_context() {
        let mut report = report();
        report.anomalies.push(AmcacheAnomaly::SuspiciousPath {
            name: "evil.exe".to_string(),
            path: r"c:\temp\evil.exe".to_string(),
            sha1: Some("0123456789012345678901234567890123456789".to_string()),
        });
        let mut output = Vec::new();
        write_jsonl(
            &mut output,
            "Amcache.hve",
            &report,
            OutputOptions::default(),
        )
        .unwrap();
        let rows: Vec<serde_json::Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(rows[1]["record_type"], "finding");
        assert_eq!(rows[1]["code"], "AMCACHE-SUSPICIOUS-PATH");
        assert_eq!(rows[1]["severity"], "medium");
        assert_eq!(rows[1]["mitre_tags"][0], "T1204");
        assert_eq!(rows[1]["subjects"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn text_details_show_metadata_only_when_selected() {
        let mut concise = Vec::new();
        write_text(&mut concise, &report(), OutputOptions::default()).unwrap();
        let concise = String::from_utf8(concise).unwrap();
        assert!(!concise.contains("publisher:"));

        let mut detailed = Vec::new();
        write_text(
            &mut detailed,
            &report(),
            OutputOptions {
                files: true,
                devices: false,
            },
        )
        .unwrap();
        let detailed = String::from_utf8(detailed).unwrap();
        assert!(detailed.contains("publisher: ACME \"Security\", Inc."));
        assert!(detailed.contains("is_os_component: false"));
    }

    #[test]
    fn csv_round_trips_quotes_newlines_unicode_and_lists() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("ys-amcache-parser-{}-{nonce}", std::process::id()));
        let paths = write_csv_directory(
            &directory,
            "Amcache.hve",
            &report(),
            OutputOptions {
                files: true,
                devices: true,
            },
        )
        .unwrap();
        assert_eq!(paths.len(), 4);

        let mut reader = csv::Reader::from_path(directory.join("Amcache_files.csv")).unwrap();
        let headers = reader.headers().unwrap().clone();
        let row = reader.records().next().unwrap().unwrap();
        assert_eq!(
            &row[headers.iter().position(|h| h == "publisher").unwrap()],
            "ACME \"Security\", Inc."
        );
        assert_eq!(
            &row[headers.iter().position(|h| h == "description").unwrap()],
            "line one\nline two"
        );
        assert!(row[headers.iter().position(|h| h == "full_path").unwrap()].contains('日'));

        let mut devices = csv::Reader::from_path(directory.join("Amcache_devices.csv")).unwrap();
        let headers = devices.headers().unwrap().clone();
        let row = devices.records().next().unwrap().unwrap();
        let hwid: Vec<String> =
            serde_json::from_str(&row[headers.iter().position(|h| h == "hwid_json").unwrap()])
                .unwrap();
        assert_eq!(hwid.len(), 2);

        // Reusing the directory without selectors must replace prior detail rows, not leave
        // apparently current evidence behind.
        write_csv_directory(
            &directory,
            "Amcache.hve",
            &report(),
            OutputOptions::default(),
        )
        .unwrap();
        let files = csv::Reader::from_path(directory.join("Amcache_files.csv"))
            .unwrap()
            .records()
            .count();
        let devices = csv::Reader::from_path(directory.join("Amcache_devices.csv"))
            .unwrap()
            .records()
            .count();
        assert_eq!(files, 0);
        assert_eq!(devices, 0);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn safe_stem_handles_windows_paths_and_unsafe_characters() {
        assert_eq!(
            safe_stem(r"C:\Windows\AppCompat\Programs\Amcache.hve"),
            "Amcache"
        );
        assert_eq!(safe_stem("/tmp/a:b.hve"), "a_b");
    }
}
