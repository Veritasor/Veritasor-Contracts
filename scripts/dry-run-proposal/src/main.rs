//! Dry-runs a protocol-dao proposal against a network (or a local Soroban
//! sandbox seeded from a forked-state snapshot — see
//! `scripts/dry_run_proposal.sh`) and reports the proposal's effect on the
//! attestation contract's DAO-visible flat fee config.
//!
//! Shells out to the `stellar` CLI for the three actual contract calls
//! (read "before", execute the proposal, read "after") rather than
//! embedding `soroban-sdk` directly, so this tool's own dependency graph
//! stays minimal and independent of the contracts workspace.
//!
//! Governance voters can run this against a proposal before casting their
//! vote to see its concrete effect, rather than having to reason about the
//! `ProposalAction` encoding by hand.

mod diff;

use diff::{diff_flat_fee_config, parse_flat_fee_config, FieldChange};
use std::process::Command;

struct Args {
    network: String,
    dao_id: String,
    attestation_id: String,
    source: String,
    executor: String,
    proposal_id: String,
    /// Test-only: read canned before/after/execute-result JSON from this
    /// directory instead of invoking the real `stellar` CLI. See
    /// `tests/fixture_run.rs`.
    fixture_dir: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut network = None;
    let mut dao_id = None;
    let mut attestation_id = None;
    let mut source = None;
    let mut executor = None;
    let mut proposal_id = None;
    let mut fixture_dir = None;

    let mut raw = std::env::args().skip(1);
    while let Some(flag) = raw.next() {
        let mut take_value = || raw.next().ok_or_else(|| format!("{flag} requires a value"));
        match flag.as_str() {
            "--network" => network = Some(take_value()?),
            "--dao-id" => dao_id = Some(take_value()?),
            "--attestation-id" => attestation_id = Some(take_value()?),
            "--source" => source = Some(take_value()?),
            "--executor" => executor = Some(take_value()?),
            "--proposal-id" => proposal_id = Some(take_value()?),
            "--fixture-dir" => fixture_dir = Some(take_value()?),
            other => return Err(format!("unrecognized argument: {other}")),
        }
    }

    // Fixture mode only needs the proposal id (it drives which canned
    // execute-result fixture file to read); everything else is a no-op
    // placeholder since no real CLI call is made.
    if let Some(fixture_dir) = fixture_dir {
        return Ok(Args {
            network: network.unwrap_or_default(),
            dao_id: dao_id.unwrap_or_default(),
            attestation_id: attestation_id.unwrap_or_default(),
            source: source.unwrap_or_default(),
            executor: executor.unwrap_or_default(),
            proposal_id: proposal_id.ok_or("--proposal-id is required")?,
            fixture_dir: Some(fixture_dir),
        });
    }

    Ok(Args {
        network: network.ok_or("--network is required")?,
        dao_id: dao_id.ok_or("--dao-id is required")?,
        attestation_id: attestation_id.ok_or("--attestation-id is required")?,
        source: source.ok_or("--source is required")?,
        executor: executor.ok_or("--executor is required")?,
        proposal_id: proposal_id.ok_or("--proposal-id is required")?,
        fixture_dir: None,
    })
}

/// Result of the middle step: actually executing the proposal.
enum ExecuteOutcome {
    Applied,
    /// The proposal couldn't be executed (unknown/invalid action, not yet
    /// approved, expired, wrong network, etc.) — `reason` is the CLI's
    /// stderr, surfaced verbatim rather than swallowed.
    Failed {
        reason: String,
    },
}

fn invoke_stellar(args: &[&str]) -> Result<String, String> {
    let output = Command::new("stellar")
        .args(args)
        .output()
        .map_err(|e| format!("failed to run `stellar` CLI: {e} (is it installed and on PATH?)"))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn read_flat_fee_config(args: &Args) -> Result<Option<diff::FlatFeeConfig>, String> {
    let json = invoke_stellar(&[
        "contract",
        "invoke",
        "--network",
        &args.network,
        "--id",
        &args.attestation_id,
        "--",
        "get_effective_flat_fee_config",
    ])?;
    parse_flat_fee_config(&json).map_err(|e| {
        format!("could not parse attestation contract response: {e}\nraw response: {json}")
    })
}

fn execute_proposal(args: &Args) -> ExecuteOutcome {
    let result = invoke_stellar(&[
        "contract",
        "invoke",
        "--network",
        &args.network,
        "--id",
        &args.dao_id,
        "--source",
        &args.source,
        "--",
        "execute_proposal",
        "--executor",
        &args.executor,
        "--id",
        &args.proposal_id,
    ]);
    match result {
        Ok(_) => ExecuteOutcome::Applied,
        Err(reason) => ExecuteOutcome::Failed { reason },
    }
}

fn print_report(proposal_id: &str, changes: &[FieldChange]) {
    println!("=== Dry run: proposal #{proposal_id} ===");
    println!("Attestation contract effect (get_effective_flat_fee_config):");
    if changes.is_empty() {
        println!("  (no observable change)");
    } else {
        for change in changes {
            println!("  {change}");
        }
    }
}

/// Reads `<dir>/before.json` and `<dir>/after.json`, and optionally
/// `<dir>/execute_error.txt` (if present, its contents are treated as the
/// stellar CLI's stderr from a failed `execute_proposal` call — this is how
/// `tests/fixture_run.rs` exercises the "proposal referencing unknown
/// method" / execution-failure edge case without a real network).
fn run_fixture(args: &Args) -> i32 {
    let dir = args
        .fixture_dir
        .as_deref()
        .expect("fixture_dir checked by caller");

    let error_path = format!("{dir}/execute_error.txt");
    if let Ok(reason) = std::fs::read_to_string(&error_path) {
        eprintln!("proposal execution failed: {}", reason.trim());
        return 1;
    }

    let before_json = std::fs::read_to_string(format!("{dir}/before.json"))
        .unwrap_or_else(|e| panic!("cannot read {dir}/before.json: {e}"));
    let after_json = std::fs::read_to_string(format!("{dir}/after.json"))
        .unwrap_or_else(|e| panic!("cannot read {dir}/after.json: {e}"));

    let before = parse_flat_fee_config(&before_json).expect("invalid before.json fixture");
    let after = parse_flat_fee_config(&after_json).expect("invalid after.json fixture");

    let changes = diff_flat_fee_config(before.as_ref(), after.as_ref());
    print_report(&args.proposal_id, &changes);
    0
}

fn run(args: &Args) -> i32 {
    if args.fixture_dir.is_some() {
        return run_fixture(args);
    }

    let before = match read_flat_fee_config(args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("failed to read attestation contract state before the proposal: {e}");
            return 1;
        }
    };

    match execute_proposal(args) {
        ExecuteOutcome::Failed { reason } => {
            eprintln!("proposal execution failed: {reason}");
            eprintln!(
                "(no state was changed against the target network — this is a read+simulate \
                 dry run; run against a local sandbox fork, never against a live network you \
                 don't control, per scripts/dry_run_proposal.sh)"
            );
            return 1;
        }
        ExecuteOutcome::Applied => {}
    }

    let after = match read_flat_fee_config(args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "proposal executed, but failed to read attestation contract state after: {e}"
            );
            return 1;
        }
    };

    let changes = diff_flat_fee_config(before.as_ref(), after.as_ref());
    print_report(&args.proposal_id, &changes);
    0
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!(
                "usage: dry-run-proposal --network <name> --dao-id <id> --attestation-id <id> \
                 --source <account> --executor <address> --proposal-id <id>"
            );
            std::process::exit(2);
        }
    };
    std::process::exit(run(&args));
}
