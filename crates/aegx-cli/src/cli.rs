//!
//! Unified CLI for AEGX evidence workflows and AER runtime protection.
//! Now includes first-class daemon management for the always-on `aegxd`
//! service and its authenticated Unix-socket IPC layer.

use aegx_daemon::{DaemonCommand, DaemonStatusSnapshot};
use clap::{Parser, Subcommand};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};
use std::thread;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "aegx")]
#[command(about = "AEGX — Provenable Recursive Verifiable Guardrails for Agentic AI")]
#[command(version = "0.2.0")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize AEGX in the current Provenable.ai state directory
    Init,
    /// Snapshot management
    Snapshot {
        #[command(subcommand)]
        action: SnapshotAction,
    },
    /// Rollback to a previous snapshot
    Rollback {
        /// Snapshot ID to rollback to
        snapshot_id: String,
    },
    /// Export an AEGX evidence bundle
    Bundle {
        #[command(subcommand)]
        action: BundleAction,
    },
    /// Verify an AEGX evidence bundle
    Verify {
        /// Path to the bundle .aegx.zip file
        bundle_path: String,
    },
    /// Generate a report from an AEGX evidence bundle
    Report {
        /// Path to the bundle .aegx.zip file
        bundle_path: String,
    },
    /// Query what Provenable.ai has protected — the /prove interface
    Prove {
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        until: Option<String>,
        #[arg(long)]
        category: Option<String>,
        #[arg(long)]
        severity: Option<String>,
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        json: bool,
    },
    /// Show AEGX status
    Status,
    /// Run live self-verification against the active runtime, optionally with active guard probes
    SelfVerify {
        #[arg(long)]
        active: bool,
        #[arg(long)]
        json: bool,
    },
    /// Manage the always-on aegxd daemon and authenticated IPC layer
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },
}

#[derive(Subcommand)]
pub enum SnapshotAction {
    /// Create a new snapshot
    Create {
        name: String,
        #[arg(long, default_value = "full")]
        scope: String,
    },
    /// List existing snapshots
    List,
}

#[derive(Subcommand)]
pub enum BundleAction {
    /// Export an evidence bundle
    Export {
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        since: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum DaemonAction {
    /// Run aegxd in the foreground
    Run,
    /// Start aegxd in the background and wait for the IPC socket to come online
    Start,
    /// Stop the running daemon via authenticated IPC
    Stop,
    /// Ping the daemon over the authenticated IPC socket
    Ping,
    /// Show live daemon status, or the last persisted status snapshot if unreachable
    Status,
    /// Reload the default guard policy inside the running daemon
    ReloadPolicy,
    /// Emit a daemon heartbeat record
    Heartbeat {
        #[arg(long, default_value = "cli")]
        agent_id: String,
        #[arg(long, default_value = "default")]
        session_id: String,
    },
}

/// Run the CLI.
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => init_run()?,
        Commands::Snapshot { action } => match action {
            SnapshotAction::Create { name, scope } => snapshot_create(&name, &scope)?,
            SnapshotAction::List => snapshot_list()?,
        },
        Commands::Rollback { snapshot_id } => snapshot_rollback(&snapshot_id)?,
        Commands::Bundle { action } => match action {
            BundleAction::Export { agent, since } => {
                bundle_export(agent.as_deref(), since.as_deref())?
            }
        },
        Commands::Verify { bundle_path } => bundle_verify(&bundle_path)?,
        Commands::Report { bundle_path } => prove_report(&bundle_path)?,
        Commands::Prove {
            since,
            until,
            category,
            severity,
            limit,
            json,
        } => prove_run(
            since.as_deref(),
            until.as_deref(),
            category.as_deref(),
            severity.as_deref(),
            limit,
            json,
        )?,
        Commands::Status => status()?,
        Commands::SelfVerify { active, json } => self_verify_run(active, json)?,
        Commands::Daemon { action } => match action {
            DaemonAction::Run => daemon_run()?,
            DaemonAction::Start => daemon_start()?,
            DaemonAction::Stop => daemon_stop()?,
            DaemonAction::Ping => daemon_ping()?,
            DaemonAction::Status => daemon_status_command()?,
            DaemonAction::ReloadPolicy => daemon_reload_policy()?,
            DaemonAction::Heartbeat {
                agent_id,
                session_id,
            } => daemon_heartbeat(&agent_id, &session_id)?,
        },
    }

    Ok(())
}

fn init_run() -> Result<(), Box<dyn std::error::Error>> {
    println!("Initializing AEGX...");

    aegx_records::ensure_aer_dirs()?;
    println!(
        "  Created AEGX directories under {}",
        aegx_records::config::aer_root().display()
    );

    let default = aegx_guard::default_policy();
    let policy_path = aegx_records::config::default_policy_file();
    aegx_guard::save_policy(&default, &policy_path)?;
    println!("  Installed default policy: {}", policy_path.display());

    aegx_runtime::ensure_workspace()?;
    println!(
        "  Ensured workspace directory: {}",
        aegx_records::config::workspace_dir().display()
    );

    println!();
    println!("AEGX initialized successfully.");
    println!();
    println!("Policy summary:");
    println!("  - CPI: deny control-plane changes from non-USER/SYS principals");
    println!("  - MI: deny memory writes with tainted provenance");
    println!("  - MI: deny memory writes from untrusted principals");
    println!("  - CIO: deny injection-suspected conversation messages");
    println!("  - All clean operations: allowed");
    println!();
    println!(
        "State directory: {}",
        aegx_records::resolve_state_dir().display()
    );
    println!(
        "Daemon runtime directory: {}",
        aegx_records::config::runtime_dir().display()
    );

    Ok(())
}

fn status() -> Result<(), Box<dyn std::error::Error>> {
    let aer_root = aegx_records::config::aer_root();
    if !aer_root.exists() {
        println!("AEGX: not initialized");
        println!("Run `aegx init` to set up AEGX.");
        return Ok(());
    }

    println!("AEGX: initialized");
    println!(
        "State directory: {}",
        aegx_records::resolve_state_dir().display()
    );
    println!("AEGX root: {}", aer_root.display());

    let record_count = aegx_records::records::record_count()?;
    println!("Records: {}", record_count);

    let entries = aegx_records::audit_chain::read_all_entries()?;
    println!("Audit chain entries: {}", entries.len());

    let snapshots = aegx_runtime::list_snapshots()?;
    println!("Snapshots: {}", snapshots.len());

    match aegx_records::audit_chain::verify_chain()? {
        Ok(_) => println!("Audit chain: VALID"),
        Err(e) => println!("Audit chain: BROKEN — {e}"),
    }

    match daemon_status_with_fallback()? {
        Some((status, true)) => {
            println!("Daemon: RUNNING (live IPC)");
            print_daemon_status(&status);
        }
        Some((status, false)) => {
            println!("Daemon: UNREACHABLE (showing persisted status snapshot)");
            print_daemon_status(&status);
        }
        None => println!("Daemon: not running"),
    }

    Ok(())
}

fn snapshot_create(name: &str, scope_str: &str) -> Result<(), Box<dyn std::error::Error>> {
    let scope = match scope_str {
        "full" => aegx_types::SnapshotScope::Full,
        "control-plane" | "cp" => aegx_types::SnapshotScope::ControlPlane,
        "memory" | "mem" => aegx_types::SnapshotScope::DurableMemory,
        _ => {
            eprintln!("Unknown scope: {scope_str}. Use: full, control-plane, memory");
            return Err("Invalid scope".into());
        }
    };

    println!("Creating snapshot '{name}' (scope: {scope_str})...");
    let manifest = aegx_runtime::create_snapshot(name, scope)?;

    println!("Snapshot created:");
    println!("  ID: {}", manifest.snapshot_id);
    println!("  Name: {}", manifest.name);
    println!("  Files: {}", manifest.files.len());
    println!("  Created: {}", manifest.created_at.to_rfc3339());

    Ok(())
}

fn snapshot_list() -> Result<(), Box<dyn std::error::Error>> {
    let snapshots = aegx_runtime::list_snapshots()?;
    if snapshots.is_empty() {
        println!("No snapshots found.");
        return Ok(());
    }
    println!("Snapshots:");
    for s in &snapshots {
        println!(
            "  {} — {} ({:?}, {} files, {})",
            &s.snapshot_id[..8],
            s.name,
            s.scope,
            s.files.len(),
            s.created_at.to_rfc3339()
        );
    }
    Ok(())
}

fn snapshot_rollback(snapshot_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = aegx_runtime::load_snapshot(snapshot_id)?;
    let (modified, _added, removed) = aegx_runtime::diff_snapshot(&manifest)?;

    println!(
        "Rolling back to snapshot: {} ({})",
        &snapshot_id[..8.min(snapshot_id.len())],
        manifest.name
    );
    println!("  Files to restore: {}", modified.len());
    println!("  Files to recreate: {}", removed.len());

    if modified.is_empty() && removed.is_empty() {
        println!("  No changes needed — state matches snapshot.");
        return Ok(());
    }

    let report = aegx_runtime::rollback_policy::rollback_to_snapshot(snapshot_id)?;
    println!();
    println!("Rollback complete:");
    if !report.files_restored.is_empty() {
        println!("  Restored:");
        for f in &report.files_restored {
            println!("    {f}");
        }
    }
    if !report.files_recreated.is_empty() {
        println!("  Recreated:");
        for f in &report.files_recreated {
            println!("    {f}");
        }
    }
    if !report.errors.is_empty() {
        println!("  Errors:");
        for e in &report.errors {
            println!("    {e}");
        }
    }

    let verified = aegx_runtime::rollback_policy::verify_rollback(snapshot_id)?;
    if verified {
        println!("  Verification: PASS");
    } else {
        println!("  Verification: FAIL");
    }

    Ok(())
}

fn bundle_export(
    agent_id: Option<&str>,
    since: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let since_dt = match since {
        Some(s) => Some(
            chrono::DateTime::parse_from_rfc3339(s)
                .map_err(|e| format!("Invalid timestamp '{s}': {e}"))?
                .with_timezone(&chrono::Utc),
        ),
        None => None,
    };

    println!("Exporting AEGX evidence bundle...");
    let bundle_path = aegx_bundle::export_bundle(agent_id, since_dt)?;
    println!("Bundle exported: {bundle_path}");
    Ok(())
}

fn bundle_verify(bundle_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(bundle_path);
    if !path.exists() {
        eprintln!("Bundle not found: {bundle_path}");
        return Err("Bundle not found".into());
    }

    println!("Verifying bundle: {bundle_path}");
    let tmp = aegx_bundle::extract_bundle(path)?;
    let result = aegx_bundle::verify_bundle(tmp.path())?;

    println!("Verification result:");
    println!("  Valid: {}", result.valid);
    println!("  Records checked: {}", result.record_count);
    println!("  Audit entries checked: {}", result.audit_entries_checked);
    println!("  Blobs checked: {}", result.blobs_checked);

    if !result.errors.is_empty() {
        println!("  Errors:");
        for e in &result.errors {
            println!("    [{:?}] {}", e.kind, e.detail);
        }
    }

    if result.valid {
        println!("\nPASS: Bundle integrity verified.");
    } else {
        println!("\nFAIL: Bundle integrity check failed.");
        std::process::exit(1);
    }

    Ok(())
}

fn prove_report(bundle_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(bundle_path);
    if !path.exists() {
        eprintln!("Bundle not found: {bundle_path}");
        return Err("Bundle not found".into());
    }

    let tmp = aegx_bundle::extract_bundle(path)?;
    let report_md_path = tmp.path().join("report.md");
    if report_md_path.exists() {
        let content = std::fs::read_to_string(&report_md_path)?;
        println!("{content}");
        return Ok(());
    }

    let records_path = tmp.path().join("records.jsonl");
    let audit_path = tmp.path().join("audit-log.jsonl");

    let records = aegx_records::records::read_records_from_path(&records_path)?;
    let audit_entries = aegx_records::audit_chain::read_entries_from_path(&audit_path)?;

    let report = aegx_bundle::report::generate_markdown_report(&records, &audit_entries);
    println!("{report}");

    Ok(())
}

fn prove_run(
    since: Option<&str>,
    until: Option<&str>,
    category: Option<&str>,
    severity: Option<&str>,
    limit: Option<usize>,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use aegx_guard::alerts::{AlertSeverity, ThreatCategory};
    use aegx_runtime::prove::{self, ProveQuery};

    let since_dt = match since {
        Some(s) => Some(
            chrono::DateTime::parse_from_rfc3339(s)
                .map_err(|e| format!("Invalid --since timestamp: {e}"))?
                .with_timezone(&chrono::Utc),
        ),
        None => None,
    };

    let until_dt = match until {
        Some(s) => Some(
            chrono::DateTime::parse_from_rfc3339(s)
                .map_err(|e| format!("Invalid --until timestamp: {e}"))?
                .with_timezone(&chrono::Utc),
        ),
        None => None,
    };

    let category_filter = match category {
        Some(c) => match c.to_lowercase().as_str() {
            "cpi" => Some(ThreatCategory::CpiViolation),
            "mi" => Some(ThreatCategory::MiViolation),
            "taint" => Some(ThreatCategory::TaintBlock),
            "injection" => Some(ThreatCategory::InjectionSuspect),
            "extraction" => Some(ThreatCategory::PromptExtraction),
            "leakage" => Some(ThreatCategory::PromptLeakage),
            "proxy" => Some(ThreatCategory::ProxyMisconfig),
            "rollback" => Some(ThreatCategory::AutoRollback),
            "contamination" => Some(ThreatCategory::ContaminationDetected),
            _ => {
                eprintln!("Unknown category: {c}. Use: cpi, mi, taint, injection, extraction, leakage, proxy, rollback, contamination");
                return Err("Invalid category".into());
            }
        },
        None => None,
    };

    let severity_filter = match severity {
        Some(s) => match s.to_lowercase().as_str() {
            "critical" => Some(AlertSeverity::Critical),
            "high" => Some(AlertSeverity::High),
            "medium" => Some(AlertSeverity::Medium),
            "info" => Some(AlertSeverity::Info),
            _ => {
                eprintln!("Unknown severity: {s}. Use: critical, high, medium, info");
                return Err("Invalid severity".into());
            }
        },
        None => None,
    };

    let query = ProveQuery {
        since: since_dt,
        until: until_dt,
        category: category_filter,
        severity_min: severity_filter,
        limit,
        include_metrics: true,
        include_health: true,
    };

    let response = prove::execute_query(&query)?;

    if json_output {
        let json = serde_json::to_string_pretty(&response)?;
        println!("{json}");
    } else {
        let formatted = prove::format_prove_response(&response);
        print!("{formatted}");
    }

    Ok(())
}

fn self_verify_run(active: bool, json_output: bool) -> Result<(), Box<dyn std::error::Error>> {
    let mode = if active {
        aegx_runtime::SelfVerificationMode::Active
    } else {
        aegx_runtime::SelfVerificationMode::Passive
    };

    let report = aegx_runtime::run_self_verification(mode)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", aegx_runtime::format_self_verification_report(&report));
    }

    if !report.overall_ok {
        std::process::exit(1);
    }

    Ok(())
}

fn daemon_run() -> Result<(), Box<dyn std::error::Error>> {
    println!("Running aegxd in the foreground...");
    aegx_daemon::run_daemon()?;
    Ok(())
}

fn daemon_start() -> Result<(), Box<dyn std::error::Error>> {
    if let Ok(response) = aegx_daemon::send_request(DaemonCommand::Ping) {
        println!("Daemon already running: {}", response.message);
        if let Some(status) = response.status {
            print_daemon_status(&status);
        }
        return Ok(());
    }

    let daemon_bin = resolve_aegxd_binary()?;
    let _child = ProcessCommand::new(&daemon_bin)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Failed to launch {}: {e}", daemon_bin.display()))?;

    for _ in 0..50 {
        thread::sleep(Duration::from_millis(100));
        if let Ok(response) = aegx_daemon::send_request(DaemonCommand::Ping) {
            println!("Daemon started successfully.");
            if let Some(status) = response.status {
                print_daemon_status(&status);
            }
            return Ok(());
        }
    }

    Err("Timed out waiting for aegxd to create a responsive IPC socket".into())
}

fn daemon_stop() -> Result<(), Box<dyn std::error::Error>> {
    let response = aegx_daemon::send_request(DaemonCommand::Stop)?;
    println!("{}", response.message);
    Ok(())
}

fn daemon_ping() -> Result<(), Box<dyn std::error::Error>> {
    let response = aegx_daemon::send_request(DaemonCommand::Ping)?;
    println!("{}", response.message);
    if let Some(status) = response.status {
        print_daemon_status(&status);
    }
    Ok(())
}

fn daemon_status_command() -> Result<(), Box<dyn std::error::Error>> {
    match daemon_status_with_fallback()? {
        Some((status, true)) => {
            println!("Daemon is reachable over authenticated IPC.");
            print_daemon_status(&status);
        }
        Some((status, false)) => {
            println!(
                "Daemon is not currently reachable; showing the last persisted status snapshot."
            );
            print_daemon_status(&status);
        }
        None => {
            println!("No daemon status is available.");
        }
    }
    Ok(())
}

fn daemon_reload_policy() -> Result<(), Box<dyn std::error::Error>> {
    let response = aegx_daemon::send_request(DaemonCommand::ReloadPolicy)?;
    println!("{}", response.message);
    if let Some(status) = response.status {
        print_daemon_status(&status);
    }
    if !response.ok {
        return Err(response.message.into());
    }
    Ok(())
}

fn daemon_heartbeat(agent_id: &str, session_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    let response = aegx_daemon::send_request(DaemonCommand::Heartbeat {
        agent_id: agent_id.to_string(),
        session_id: session_id.to_string(),
    })?;
    println!("{}", response.message);
    if let Some(record_id) = response.record_id {
        println!("Heartbeat record: {record_id}");
    }
    if let Some(status) = response.status {
        print_daemon_status(&status);
    }
    Ok(())
}

fn daemon_status_with_fallback(
) -> Result<Option<(DaemonStatusSnapshot, bool)>, Box<dyn std::error::Error>> {
    match aegx_daemon::send_request(DaemonCommand::Status) {
        Ok(response) => Ok(response.status.map(|status| (status, true))),
        Err(_) => match aegx_daemon::read_status_file() {
            Ok(status) => Ok(Some((status, false))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Box::new(e)),
        },
    }
}

fn print_daemon_status(status: &DaemonStatusSnapshot) {
    println!("  PID: {}", status.pid);
    println!("  Socket: {}", status.socket_path);
    println!("  Started: {}", status.started_at.to_rfc3339());
    println!("  Uptime seconds: {}", status.uptime_seconds);
    println!("  Policy loaded: {}", status.policy_loaded);
    println!("  Records: {}", status.record_count);
    println!("  Alerts: {}", status.alert_count);
    println!("  Audit chain valid: {}", status.audit_chain_valid);
    println!("  Heartbeats: {}", status.heartbeat_count);
    println!("  Events processed: {}", status.events_processed);
    if let Some(ts) = status.last_request_at {
        println!("  Last request: {}", ts.to_rfc3339());
    }
    if let Some(ts) = status.last_heartbeat_at {
        println!("  Last heartbeat: {}", ts.to_rfc3339());
    }
    if let Some(ref audit) = status.sandbox_audit {
        println!("  Sandbox compliance: {:?}", audit.compliance);
    }
    if let Some(ref err) = status.policy_error {
        println!("  Policy error: {err}");
    }
    if let Some(ref err) = status.audit_chain_error {
        println!("  Audit chain error: {err}");
    }
    if !status.degraded_reasons.is_empty() {
        println!("  Degraded reasons:");
        for reason in &status.degraded_reasons {
            println!("    - {reason}");
        }
    }
}

fn resolve_aegxd_binary() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let current = std::env::current_exe()?;
    let sibling = current.with_file_name("aegxd");
    if sibling.exists() {
        return Ok(sibling);
    }
    Ok(PathBuf::from("aegxd"))
}
