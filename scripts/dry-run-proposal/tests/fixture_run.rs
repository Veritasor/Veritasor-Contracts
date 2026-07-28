//! End-to-end tests of the actual compiled `dry-run-proposal` binary,
//! using `--fixture-dir` to avoid depending on a real `stellar` CLI or
//! network. This exercises the real argument parsing, process exit code,
//! and stdout/stderr output — not just the internal `diff` module.

use std::path::PathBuf;
use std::process::Command;

fn fixture_path(name: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/fixtures");
    path.push(name);
    path.to_string_lossy().into_owned()
}

fn run_binary(fixture: &str, proposal_id: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_dry-run-proposal"))
        .args([
            "--fixture-dir",
            &fixture_path(fixture),
            "--proposal-id",
            proposal_id,
        ])
        .output()
        .expect("failed to run dry-run-proposal binary")
}

#[test]
fn reports_no_change_when_config_is_identical() {
    let output = run_binary("no_change", "1");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("proposal #1"));
    assert!(stdout.contains("(no observable change)"));
}

#[test]
fn reports_amount_and_enabled_changes() {
    let output = run_binary("amount_and_enabled_change", "42");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("proposal #42"));
    assert!(stdout.contains("amount: 1000 -> 5000"));
    assert!(stdout.contains("enabled: true -> false"));
}

#[test]
fn reports_config_being_newly_set() {
    let output = run_binary("config_newly_set", "7");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("config: unset ->"));
}

#[test]
fn exits_nonzero_and_reports_reason_when_execution_fails() {
    // Covers the "proposal referencing unknown method" / execution-failure
    // edge case: the tool must fail loudly with the CLI's actual error
    // rather than panicking or silently reporting no changes.
    let output = run_binary("execution_fails", "99");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("proposal execution failed"));
    assert!(stderr.contains("proposal is not pending"));
}

#[test]
fn missing_proposal_id_is_a_usage_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_dry-run-proposal"))
        .args(["--fixture-dir", &fixture_path("no_change")])
        .output()
        .expect("failed to run dry-run-proposal binary");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--proposal-id is required"));
}

#[test]
fn unrecognized_flag_is_a_usage_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_dry-run-proposal"))
        .args(["--not-a-real-flag", "value"])
        .output()
        .expect("failed to run dry-run-proposal binary");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unrecognized argument"));
}
