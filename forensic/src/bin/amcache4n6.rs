//! `amcache4n6` — cross-platform Windows `Amcache.hve` parser and forensic analyzer.
#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use amcache_forensic::analyze_bytes;
use amcache_forensic::output::{
    write_csv_directory, write_json, write_jsonl, write_text, OutputOptions,
};

const USAGE: &str = "\
Cross-platform Windows Amcache.hve parser and forensic analyzer

Usage: amcache4n6 [OPTIONS] <Amcache.hve>

Options:
      --files              Add complete file-entry records
      --devices            Add complete device-entry records
      --all                Add both file and device records
      --format <FORMAT>    Output format: text, json, jsonl, or csv [default: text]
  -o, --output <PATH>      Output file, or output directory for CSV [default: stdout]
  -h, --help               Print help
  -V, --version            Print version

Summary and findings are always included; selectors add detailed records. CSV output
requires --output <DIRECTORY> because record types use separate tables. Structured
stdout contains only output data.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Text,
    Json,
    Jsonl,
    Csv,
}

impl OutputFormat {
    fn parse(value: &str) -> Result<Self, String> {
        match value.to_ascii_lowercase().as_str() {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            "jsonl" => Ok(Self::Jsonl),
            "csv" => Ok(Self::Csv),
            _ => Err(format!(
                "unsupported output format {value:?}; expected text, json, jsonl, or csv"
            )),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Cli {
    input: PathBuf,
    files: bool,
    devices: bool,
    format: OutputFormat,
    output: Option<PathBuf>,
}

enum ParseResult {
    Run(Cli),
    Help,
    Version,
}

fn main() -> ExitCode {
    match parse_args(std::env::args_os().skip(1)) {
        Ok(ParseResult::Help) => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Ok(ParseResult::Version) => {
            println!("amcache4n6 {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Ok(ParseResult::Run(cli)) => match run(&cli) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("amcache4n6: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("amcache4n6: {error}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn parse_args(args: impl IntoIterator<Item = OsString>) -> Result<ParseResult, String> {
    let mut args = args.into_iter();
    let mut input = None;
    let mut files = false;
    let mut devices = false;
    let mut format = OutputFormat::Text;
    let mut output = None;
    let mut positional_only = false;

    while let Some(raw) = args.next() {
        let arg = raw
            .into_string()
            .map_err(|_| "arguments must be valid Unicode".to_string())?;
        if positional_only {
            if input.is_some() {
                return Err(format!("unexpected second input path {arg:?}"));
            }
            input = Some(PathBuf::from(arg));
            continue;
        }
        match arg.as_str() {
            "--" => positional_only = true,
            "-h" | "--help" => return Ok(ParseResult::Help),
            "-V" | "--version" => return Ok(ParseResult::Version),
            "--files" => files = true,
            "--devices" => devices = true,
            "--all" => {
                files = true;
                devices = true;
            }
            "--format" => {
                let value = next_value(&mut args, "--format")?;
                format = OutputFormat::parse(&value)?;
            }
            "-o" | "--output" => {
                output = Some(PathBuf::from(next_value(&mut args, arg.as_str())?));
            }
            _ if arg.starts_with("--format=") => {
                format = OutputFormat::parse(&arg["--format=".len()..])?;
            }
            _ if arg.starts_with("--output=") => {
                output = Some(PathBuf::from(&arg["--output=".len()..]));
            }
            _ if arg.starts_with('-') => return Err(format!("unknown option {arg:?}")),
            _ if input.is_some() => {
                return Err(format!("unexpected second input path {arg:?}"));
            }
            _ => input = Some(PathBuf::from(arg)),
        }
    }

    let input = input.ok_or_else(|| "missing Amcache.hve input path".to_string())?;
    if format == OutputFormat::Csv {
        match output.as_deref() {
            None => return Err("CSV output requires --output <DIRECTORY>".to_string()),
            Some(path) if path.as_os_str() == "-" => {
                return Err(
                    "CSV output cannot use stdout; specify --output <DIRECTORY>".to_string()
                );
            }
            Some(_) => {}
        }
    }

    Ok(ParseResult::Run(Cli {
        input,
        files,
        devices,
        format,
        output,
    }))
}

fn next_value(args: &mut impl Iterator<Item = OsString>, option: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{option} requires a value"))?
        .into_string()
        .map_err(|_| format!("{option} value must be valid Unicode"))
}

fn run(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(output) = cli.output.as_deref() {
        if output.as_os_str() != "-" && paths_refer_to_same_file(&cli.input, output) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "input and output paths refer to the same file",
            )
            .into());
        }
    }
    let bytes = std::fs::read(&cli.input).map_err(|error| {
        io::Error::new(error.kind(), format!("{}: {error}", cli.input.display()))
    })?;
    let report = analyze_bytes(&bytes)?;
    let source = cli.input.to_string_lossy();
    let options = OutputOptions {
        files: cli.files,
        devices: cli.devices,
    };

    if cli.format == OutputFormat::Csv {
        let directory = cli.output.as_deref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "CSV output requires an output directory",
            )
        })?;
        let paths = write_csv_directory(directory, &source, &report, options)?;
        for path in paths {
            eprintln!("wrote {}", path.display());
        }
        return Ok(());
    }

    match cli.output.as_deref() {
        Some(path) if path.as_os_str() != "-" => {
            let file = File::create(path)?;
            let mut writer = BufWriter::new(file);
            write_selected(&mut writer, cli.format, &source, &report, options)?;
            writer.flush()?;
        }
        _ => {
            let stdout = io::stdout();
            let mut writer = stdout.lock();
            write_selected(&mut writer, cli.format, &source, &report, options)?;
            writer.flush()?;
        }
    }
    Ok(())
}

fn paths_refer_to_same_file(input: &std::path::Path, output: &std::path::Path) -> bool {
    if input == output {
        return true;
    }
    if output.exists() && same_file::is_same_file(input, output).unwrap_or(false) {
        return true;
    }
    let canonical_match = match (std::fs::canonicalize(input), std::fs::canonicalize(output)) {
        (Ok(input), Ok(output)) => input == output,
        _ => false,
    };
    if canonical_match {
        return true;
    }
    false
}

fn write_selected(
    writer: &mut impl io::Write,
    format: OutputFormat,
    source: &str,
    report: &amcache_forensic::AmcacheReport,
    options: OutputOptions,
) -> Result<(), amcache_forensic::output::OutputError> {
    match format {
        OutputFormat::Text => write_text(writer, report, options),
        OutputFormat::Json => write_json(writer, source, report, options),
        OutputFormat::Jsonl => write_jsonl(writer, source, report, options),
        OutputFormat::Csv => Err(amcache_forensic::output::OutputError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "CSV output requires a directory",
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(items: &[&str]) -> Result<ParseResult, String> {
        parse_args(items.iter().map(OsString::from))
    }

    #[test]
    fn parses_all_formats_and_selectors() {
        let ParseResult::Run(cli) = parse(&[
            "--all",
            "--format",
            "jsonl",
            "-o",
            "out.jsonl",
            "Amcache.hve",
        ])
        .expect("valid arguments") else {
            panic!("expected run arguments");
        };
        assert!(cli.files);
        assert!(cli.devices);
        assert_eq!(cli.format, OutputFormat::Jsonl);
        assert_eq!(cli.output, Some(PathBuf::from("out.jsonl")));
        assert_eq!(cli.input, PathBuf::from("Amcache.hve"));
    }

    #[test]
    fn csv_requires_a_directory_path() {
        let Err(error) = parse(&["--format=csv", "Amcache.hve"]) else {
            panic!("CSV without --output should fail");
        };
        assert!(error.contains("requires --output"));
    }

    #[test]
    fn rejects_unknown_options_and_formats() {
        let Err(unknown) = parse(&["--wat", "Amcache.hve"]) else {
            panic!("unknown option should fail");
        };
        assert!(unknown.contains("unknown option"));

        let Err(format) = parse(&["--format", "xml", "Amcache.hve"]) else {
            panic!("unknown format should fail");
        };
        assert!(format.contains("text, json, jsonl, or csv"));
    }

    #[test]
    fn recognizes_identical_input_and_output_paths() {
        let path = std::path::Path::new("Amcache.hve");
        assert!(paths_refer_to_same_file(path, path));
        assert!(!paths_refer_to_same_file(
            path,
            std::path::Path::new("output.json")
        ));
    }

    #[test]
    fn double_dash_allows_a_dash_prefixed_input_path() {
        let ParseResult::Run(cli) = parse(&["--files", "--", "-evidence.hve"])
            .expect("double dash should end option parsing")
        else {
            panic!("expected run arguments");
        };
        assert!(cli.files);
        assert_eq!(cli.input, PathBuf::from("-evidence.hve"));
    }

    #[test]
    fn recognizes_hard_link_aliases() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after Unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "ys-amcache-same-file-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).expect("create test directory");
        let input = directory.join("input.hve");
        let alias = directory.join("alias.hve");
        std::fs::write(&input, b"evidence").expect("create test input");
        std::fs::hard_link(&input, &alias).expect("create hard link");
        assert!(paths_refer_to_same_file(&input, &alias));
        std::fs::remove_dir_all(directory).expect("remove test directory");
    }
}
