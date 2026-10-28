//! End-to-end CLI contract tests using the committed Windows 10 Amcache fixture.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const HIVE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../core/tests/data/amcache_win10.hve"
);

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ys-amcache-parser"))
}

fn temp_directory(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "ys-amcache-cli-{label}-{}-{nonce}",
        std::process::id()
    ))
}

#[test]
fn json_stdout_is_uncontaminated_and_complete() {
    let output = command()
        .args(["--files", "--format", "json", HIVE])
        .output()
        .expect("run ys-amcache-parser");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());

    let document: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout is one JSON document");
    assert_eq!(document["summary"]["file_count"], 123);
    assert_eq!(document["summary"]["device_count"], 189);
    assert_eq!(document["files"].as_array().unwrap().len(), 123);
    assert!(document["devices"].as_array().unwrap().is_empty());
    assert!(!document["findings"].as_array().unwrap().is_empty());
}

#[test]
fn invalid_format_is_a_usage_error() {
    let output = command()
        .args(["--format", "xml", HIVE])
        .output()
        .expect("run ys-amcache-parser");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("text, json, jsonl, or csv"));
}

#[test]
fn refusing_same_input_and_output_preserves_evidence() {
    let directory = temp_directory("same-file");
    std::fs::create_dir(&directory).expect("create test directory");
    let hive = directory.join("Amcache.hve");
    std::fs::copy(HIVE, &hive).expect("copy hive fixture");
    let before = std::fs::read(&hive).expect("read copied hive");

    let output = command()
        .arg("--format")
        .arg("json")
        .arg("--output")
        .arg(&hive)
        .arg(&hive)
        .output()
        .expect("run ys-amcache-parser");
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("same file"));
    assert_eq!(std::fs::read(&hive).expect("reread copied hive"), before);
    std::fs::remove_dir_all(directory).expect("remove test directory");
}
