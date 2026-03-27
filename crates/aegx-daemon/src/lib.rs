use aegx_guard::alerts::{self, AlertSeverity, NotificationLevel, NotificationSource, ThreatCategory};
use aegx_records::{audit_chain, config, records};
use aegx_runtime::{hooks, sandbox_audit};
use aegx_types::{sha256_hex, Principal, RecordMeta, RecordType, TaintFlags, TypedRecord};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatusSnapshot {
    pub status_version: String,
    pub pid: u32,
    pub started_at: DateTime<Utc>,
    pub uptime_seconds: u64,
    pub socket_path: String,
    pub initialized: bool,
    pub auth_token_present: bool,
    pub policy_file: String,
    pub policy_sha256: Option<String>,
    pub policy_loaded: bool,
    pub policy_error: Option<String>,
    pub record_count: u64,
    pub alert_count: u64,
    pub audit_chain_valid: bool,
    pub audit_chain_error: Option<String>,
    pub heartbeat_count: u64,
    pub events_processed: u64,
    pub last_request_at: Option<DateTime<Utc>>,
    pub last_heartbeat_at: Option<DateTime<Utc>>,
    pub heartbeat_stale: bool,
    pub bypass_attempt_count: u64,
    pub last_bypass_attempt_at: Option<DateTime<Utc>>,
    pub sandbox_audit: Option<sandbox_audit::SandboxAuditResult>,
    pub degraded_reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonRequest {
    pub token: String,
    #[serde(flatten)]
    pub command: DaemonCommand,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum DaemonCommand {
    Ping,
    Stop,
    Status,
    ReloadPolicy,
    Heartbeat {
        agent_id: String,
        session_id: String,
    },
    Event {
        event: RuntimeEvent,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RuntimeEvent {
    SessionStart {
        agent_id: String,
        session_id: String,
        channel: String,
        ip: Option<String>,
    },
    SessionMessage {
        agent_id: String,
        session_id: String,
        principal: Principal,
        taint: TaintFlags,
        content: serde_json::Value,
        parent_records: Vec<String>,
    },
    ToolCall {
        agent_id: String,
        session_id: String,
        tool_id: String,
        principal: Principal,
        taint: TaintFlags,
        arguments: serde_json::Value,
        parent_records: Vec<String>,
    },
    ToolResult {
        agent_id: String,
        session_id: String,
        tool_id: String,
        principal: Principal,
        taint: TaintFlags,
        result: serde_json::Value,
        parent_records: Vec<String>,
    },
    ControlPlaneChange {
        principal: Principal,
        taint: TaintFlags,
        approved: bool,
        config_key: String,
        change_detail: serde_json::Value,
        parent_records: Vec<String>,
    },
    FileWrite {
        principal: Principal,
        taint: TaintFlags,
        approved: bool,
        file_path: String,
        content: String,
        parent_records: Vec<String>,
        apply_write: bool,
    },
    ProxyTrustCheck {
        trusted_proxies: Vec<String>,
        gateway_addr: String,
    },
    SkillInstall {
        principal: Principal,
        taint: TaintFlags,
        package: SkillPackageInput,
        existing_skills: Vec<String>,
        popular_skills: Vec<String>,
        parent_records: Vec<String>,
    },
    MessageInput {
        agent_id: String,
        session_id: String,
        principal: Principal,
        taint: TaintFlags,
        content: String,
        parent_records: Vec<String>,
    },
    MessageOutput {
        agent_id: String,
        session_id: String,
        content: String,
        parent_records: Vec<String>,
    },
    SystemPromptAvailable {
        agent_id: String,
        session_id: String,
        system_prompt: String,
    },
    FileRead {
        agent_id: String,
        session_id: String,
        principal: Principal,
        taint: TaintFlags,
        file_path: String,
        parent_records: Vec<String>,
    },
    OutboundRequest {
        agent_id: String,
        session_id: String,
        principal: Principal,
        taint: TaintFlags,
        url: String,
        method: String,
        payload_size: usize,
        parent_records: Vec<String>,
    },
    SandboxAudit {
        agent_id: String,
        session_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillPackageInput {
    pub name: String,
    pub skill_md: String,
    pub code_files: Vec<SkillCodeFile>,
    pub manifest_json: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillCodeFile {
    pub filename: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonResponse {
    pub ok: bool,
    pub message: String,
    pub allowed: Option<bool>,
    pub record_id: Option<String>,
    pub status: Option<DaemonStatusSnapshot>,
    pub data: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
struct RuntimeState {
    started_at: DateTime<Utc>,
    heartbeat_count: u64,
    events_processed: u64,
    last_request_at: Option<DateTime<Utc>>,
    last_heartbeat_at: Option<DateTime<Utc>>,
    bypass_attempt_count: u64,
    last_bypass_attempt_at: Option<DateTime<Utc>>,
    sandbox_audit: Option<sandbox_audit::SandboxAuditResult>,
    degraded_reasons: Vec<String>,
    reported_degraded_reasons: Vec<String>,
}

impl RuntimeState {
    fn new() -> Self {
        Self {
            started_at: Utc::now(),
            heartbeat_count: 0,
            events_processed: 0,
            last_request_at: None,
            last_heartbeat_at: None,
            bypass_attempt_count: 0,
            last_bypass_attempt_at: None,
            sandbox_audit: None,
            degraded_reasons: Vec::new(),
            reported_degraded_reasons: Vec::new(),
        }
    }
}

type SharedState = Arc<Mutex<RuntimeState>>;

const HEARTBEAT_STALE_SECS: i64 = 300;
const MAX_DEGRADED_REASONS: usize = 32;

pub fn run_daemon() -> io::Result<()> {
    config::ensure_aer_dirs()?;
    secure_runtime_dir()?;

    let socket_path = config::daemon_socket_file();
    if socket_path.exists() {
        let _ = fs::remove_file(&socket_path);
    }

    let auth_token = ensure_auth_token()?;
    let pid = std::process::id();
    fs::write(config::daemon_pid_file(), format!("{}\n", pid))?;
    fs::set_permissions(config::daemon_pid_file(), fs::Permissions::from_mode(0o600))?;

    let state = Arc::new(Mutex::new(RuntimeState::new()));
    bootstrap_sandbox_audit(&state)?;

    let listener = UnixListener::bind(&socket_path)?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
    refresh_status_file(&state)?;

    let mut should_stop = false;
    while !should_stop {
        let (mut stream, _) = match listener.accept() {
            Ok(conn) => conn,
            Err(e) => {
                remember_degraded_reason(&state, format!("daemon listener accept failed: {e}"));
                let _ = emit_runtime_signal(
                    ThreatCategory::DaemonDegraded,
                    AlertSeverity::High,
                    format!("Daemon degraded: listener accept failed: {e}"),
                    "daemon-listener-accept",
                    "daemon_listener",
                    false,
                    Some("Inspect local processes and filesystem permissions around the daemon socket."),
                );
                continue;
            }
        };

        let response = match handle_connection(&mut stream, &auth_token, &state) {
            Ok(response) => response,
            Err(e) => {
                remember_degraded_reason(&state, format!("daemon connection handling failed: {e}"));
                let _ = emit_runtime_signal(
                    ThreatCategory::DaemonDegraded,
                    AlertSeverity::High,
                    format!("Daemon degraded: connection handling failed: {e}"),
                    "daemon-connection-error",
                    "daemon_ipc",
                    false,
                    Some("Inspect the daemon runtime directory and restart the daemon after reviewing recent alerts."),
                );
                let response = DaemonResponse {
                    ok: false,
                    message: "daemon_error".to_string(),
                    allowed: None,
                    record_id: None,
                    status: build_status_snapshot(&state).ok(),
                    data: Some(json!({ "error": e.to_string() })),
                };
                let _ = write_response(&mut stream, &response);
                response
            }
        };

        if response.message == "daemon_stopping" {
            should_stop = true;
        }
    }

    let _ = fs::remove_file(config::daemon_socket_file());
    let _ = fs::remove_file(config::daemon_pid_file());
    Ok(())
}

pub fn read_status_file() -> io::Result<DaemonStatusSnapshot> {
    let content = fs::read_to_string(config::daemon_status_file())?;
    serde_json::from_str(&content).map_err(io_other)
}

pub fn read_auth_token() -> io::Result<String> {
    let token = fs::read_to_string(config::daemon_auth_token_file())?;
    Ok(token.trim().to_string())
}

pub fn send_request(command: DaemonCommand) -> io::Result<DaemonResponse> {
    let token = read_auth_token()?;
    send_authenticated_request(command, &token)
}

pub fn send_authenticated_request(
    command: DaemonCommand,
    token: &str,
) -> io::Result<DaemonResponse> {
    let socket_path = config::daemon_socket_file();
    let mut stream = UnixStream::connect(&socket_path)?;
    let request = DaemonRequest {
        token: token.to_string(),
        command,
    };
    let body = serde_json::to_string(&request).map_err(io_other)?;
    stream.write_all(body.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    serde_json::from_str(line.trim_end()).map_err(io_other)
}

fn handle_connection(
    stream: &mut UnixStream,
    auth_token: &str,
    state: &SharedState,
) -> io::Result<DaemonResponse> {
    let mut line = String::new();
    {
        let mut reader = BufReader::new(stream.try_clone()?);
        let bytes_read = reader.read_line(&mut line)?;
        if bytes_read == 0 || line.trim().is_empty() {
            note_bypass_attempt(state, "empty IPC request received on daemon socket", "daemon_socket");
            let response = DaemonResponse {
                ok: false,
                message: "empty_request".to_string(),
                allowed: None,
                record_id: None,
                status: build_status_snapshot(state).ok(),
                data: Some(json!({ "error": "empty request" })),
            };
            let _ = write_response(stream, &response);
            return Ok(response);
        }
    }

    let request: DaemonRequest = match serde_json::from_str(line.trim_end()) {
        Ok(request) => request,
        Err(e) => {
            note_bypass_attempt(
                state,
                format!("invalid JSON request received on daemon socket: {e}"),
                "daemon_socket",
            );
            let response = DaemonResponse {
                ok: false,
                message: "invalid_request".to_string(),
                allowed: None,
                record_id: None,
                status: build_status_snapshot(state).ok(),
                data: Some(json!({ "error": e.to_string() })),
            };
            let _ = write_response(stream, &response);
            return Ok(response);
        }
    };

    if request.token != auth_token {
        note_bypass_attempt(
            state,
            "authentication token mismatch for daemon request",
            "daemon_auth_token",
        );
        let response = DaemonResponse {
            ok: false,
            message: "authentication_failed".to_string(),
            allowed: None,
            record_id: None,
            status: build_status_snapshot(state).ok(),
            data: Some(json!({ "error": "authentication failed" })),
        };
        let _ = write_response(stream, &response);
        return Ok(response);
    }

    {
        let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
        guard.last_request_at = Some(Utc::now());
    }

    let mut response = match execute_command(request.command, state) {
        Ok(response) => response,
        Err(e) => {
            remember_degraded_reason(state, format!("daemon command execution failed: {e}"));
            let _ = emit_runtime_signal(
                ThreatCategory::DaemonDegraded,
                AlertSeverity::High,
                format!("Daemon degraded: command execution failed: {e}"),
                "daemon-command-failed",
                "daemon_command",
                false,
                Some("Inspect the failing daemon command and review recent runtime evidence before retrying."),
            );
            DaemonResponse {
                ok: false,
                message: "command_failed".to_string(),
                allowed: None,
                record_id: None,
                status: build_status_snapshot(state).ok(),
                data: Some(json!({ "error": e.to_string() })),
            }
        }
    };

    if response.status.is_none() {
        response.status = build_status_snapshot(state).ok();
    }

    if let Err(e) = refresh_status_file(state) {
        remember_degraded_reason(state, format!("status snapshot refresh failed: {e}"));
        response.status = build_status_snapshot(state).ok();
    }

    write_response(stream, &response)?;
    Ok(response)
}

fn execute_command(command: DaemonCommand, state: &SharedState) -> io::Result<DaemonResponse> {
    match command {
        DaemonCommand::Ping => Ok(DaemonResponse {
            ok: true,
            message: "pong".to_string(),
            allowed: None,
            record_id: None,
            status: Some(build_status_snapshot(state)?),
            data: None,
        }),
        DaemonCommand::Stop => Ok(DaemonResponse {
            ok: true,
            message: "daemon_stopping".to_string(),
            allowed: None,
            record_id: None,
            status: Some(build_status_snapshot(state)?),
            data: None,
        }),
        DaemonCommand::Status => Ok(DaemonResponse {
            ok: true,
            message: "status".to_string(),
            allowed: None,
            record_id: None,
            status: Some(build_status_snapshot(state)?),
            data: None,
        }),
        DaemonCommand::ReloadPolicy => {
            let response = match aegx_guard::guard::Guard::load_default() {
                Ok(_) => DaemonResponse {
                    ok: true,
                    message: "policy_reloaded".to_string(),
                    allowed: None,
                    record_id: None,
                    status: Some(build_status_snapshot(state)?),
                    data: None,
                },
                Err(e) => DaemonResponse {
                    ok: false,
                    message: format!("policy_reload_failed: {e}"),
                    allowed: None,
                    record_id: None,
                    status: Some(build_status_snapshot(state)?),
                    data: None,
                },
            };
            Ok(response)
        }
        DaemonCommand::Heartbeat {
            agent_id,
            session_id,
        } => {
            let record = emit_heartbeat_record(&agent_id, &session_id)?;
            {
                let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
                guard.heartbeat_count += 1;
                guard.last_heartbeat_at = Some(Utc::now());
            }
            Ok(DaemonResponse {
                ok: true,
                message: "heartbeat_recorded".to_string(),
                allowed: Some(true),
                record_id: Some(record.record_id),
                status: Some(build_status_snapshot(state)?),
                data: None,
            })
        }
        DaemonCommand::Event { event } => execute_event(event, state),
    }
}

fn execute_event(event: RuntimeEvent, state: &SharedState) -> io::Result<DaemonResponse> {
    let response = match event {
        RuntimeEvent::SessionStart {
            agent_id,
            session_id,
            channel,
            ip,
        } => {
            let record = hooks::on_session_start(&agent_id, &session_id, &channel, ip.as_deref())?;
            simple_record_response("session_started", record)
        }
        RuntimeEvent::SessionMessage {
            agent_id,
            session_id,
            principal,
            taint,
            content,
            parent_records,
        } => {
            let record = hooks::on_session_message(
                &agent_id,
                &session_id,
                principal,
                taint,
                content,
                parent_records,
            )?;
            simple_record_response("session_message_recorded", record)
        }
        RuntimeEvent::ToolCall {
            agent_id,
            session_id,
            tool_id,
            principal,
            taint,
            arguments,
            parent_records,
        } => {
            let record = hooks::on_tool_call(
                &agent_id,
                &session_id,
                &tool_id,
                principal,
                taint,
                arguments,
                parent_records,
            )?;
            simple_record_response("tool_call_recorded", record)
        }
        RuntimeEvent::ToolResult {
            agent_id,
            session_id,
            tool_id,
            principal,
            taint,
            result,
            parent_records,
        } => {
            let record = hooks::on_tool_result(
                &agent_id,
                &session_id,
                &tool_id,
                principal,
                taint,
                result,
                parent_records,
            )?;
            simple_record_response("tool_result_recorded", record)
        }
        RuntimeEvent::ControlPlaneChange {
            principal,
            taint,
            approved,
            config_key,
            change_detail,
            parent_records,
        } => match hooks::on_control_plane_change(
            principal,
            taint,
            approved,
            &config_key,
            change_detail,
            parent_records,
        )? {
            Ok(record) => allowed_record_response("control_plane_change_allowed", true, record),
            Err(record) => allowed_record_response("control_plane_change_denied", false, record),
        },
        RuntimeEvent::FileWrite {
            principal,
            taint,
            approved,
            file_path,
            content,
            parent_records,
            apply_write,
        } => match hooks::on_file_write(
            principal,
            taint,
            approved,
            &file_path,
            content.as_bytes(),
            parent_records,
        )? {
            Ok(record) => {
                if apply_write {
                    if let Some(parent) = Path::new(&file_path).parent() {
                        fs::create_dir_all(parent)?;
                    }
                    fs::write(&file_path, content.as_bytes())?;
                }
                let mut response = allowed_record_response("file_write_allowed", true, record);
                response.data = Some(json!({
                    "apply_write": apply_write,
                    "file_path": file_path,
                    "bytes": content.len(),
                }));
                response
            }
            Err(record) => allowed_record_response("file_write_denied", false, record),
        },
        RuntimeEvent::ProxyTrustCheck {
            trusted_proxies,
            gateway_addr,
        } => {
            let maybe_record = hooks::check_proxy_trust(&trusted_proxies, &gateway_addr)?;
            DaemonResponse {
                ok: true,
                message: if maybe_record.is_some() {
                    "proxy_misconfiguration_detected"
                } else {
                    "proxy_configuration_clean"
                }
                .to_string(),
                allowed: Some(true),
                record_id: maybe_record.as_ref().map(|r| r.record_id.clone()),
                status: None,
                data: Some(json!({
                    "gateway_addr": gateway_addr,
                    "trusted_proxies": trusted_proxies,
                    "misconfigured": maybe_record.is_some(),
                })),
            }
        }
        RuntimeEvent::SkillInstall {
            principal,
            taint,
            package,
            existing_skills,
            popular_skills,
            parent_records,
        } => {
            let package = aegx_guard::skill_verifier::SkillPackage {
                name: package.name,
                skill_md: package.skill_md,
                code_files: package
                    .code_files
                    .into_iter()
                    .map(|f| (f.filename, f.content))
                    .collect(),
                manifest_json: package.manifest_json,
            };
            let existing_refs: Vec<&str> = existing_skills.iter().map(String::as_str).collect();
            let popular_refs: Vec<&str> = popular_skills.iter().map(String::as_str).collect();
            match hooks::on_skill_install(
                principal,
                taint,
                &package,
                &existing_refs,
                &popular_refs,
                parent_records,
            )? {
                Ok(record) => allowed_record_response("skill_install_allowed", true, record),
                Err(record) => allowed_record_response("skill_install_denied", false, record),
            }
        }
        RuntimeEvent::MessageInput {
            agent_id,
            session_id,
            principal,
            taint,
            content,
            parent_records,
        } => match hooks::on_message_input(
            &agent_id,
            &session_id,
            principal,
            taint,
            &content,
            parent_records,
        )? {
            Ok(record) => allowed_record_response("message_input_allowed", true, record),
            Err(record) => allowed_record_response("message_input_blocked", false, record),
        },
        RuntimeEvent::MessageOutput {
            agent_id,
            session_id,
            content,
            parent_records,
        } => match hooks::on_message_output(&agent_id, &session_id, &content, None, parent_records)? {
            Ok(record) => allowed_record_response("message_output_allowed", true, record),
            Err(record) => allowed_record_response("message_output_blocked", false, record),
        },
        RuntimeEvent::SystemPromptAvailable {
            agent_id,
            session_id,
            system_prompt,
        } => {
            let record = hooks::on_system_prompt_available(&agent_id, &session_id, &system_prompt)?;
            simple_record_response("system_prompt_registered", record)
        }
        RuntimeEvent::FileRead {
            agent_id,
            session_id,
            principal,
            taint,
            file_path,
            parent_records,
        } => match hooks::on_file_read(
            &agent_id,
            &session_id,
            principal,
            taint,
            &file_path,
            parent_records,
        )? {
            Ok(record) => {
                let mut response = allowed_record_response("file_read_allowed", true, record);
                response.data = Some(json!({
                    "file_path": file_path,
                    "exists": Path::new(&file_path).exists(),
                }));
                response
            }
            Err(record) => allowed_record_response("file_read_denied", false, record),
        },
        RuntimeEvent::OutboundRequest {
            agent_id,
            session_id,
            principal,
            taint,
            url,
            method,
            payload_size,
            parent_records,
        } => match hooks::on_outbound_request(
            &agent_id,
            &session_id,
            principal,
            taint,
            &url,
            &method,
            payload_size,
            parent_records,
        )? {
            Ok(record) => allowed_record_response("outbound_request_allowed", true, record),
            Err(record) => allowed_record_response("outbound_request_denied", false, record),
        },
        RuntimeEvent::SandboxAudit {
            agent_id,
            session_id,
        } => {
            let (audit, record) = hooks::on_sandbox_audit(&agent_id, &session_id)?;
            {
                let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
                guard.sandbox_audit = Some(audit.clone());
            }
            let mut response = simple_record_response("sandbox_audit_recorded", record);
            response.data = Some(serde_json::to_value(audit).map_err(io_other)?);
            response
        }
    };

    {
        let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
        guard.events_processed += 1;
    }

    let mut final_response = response;
    final_response.status = Some(build_status_snapshot(state)?);
    Ok(final_response)
}

fn simple_record_response(message: &str, record: TypedRecord) -> DaemonResponse {
    DaemonResponse {
        ok: true,
        message: message.to_string(),
        allowed: Some(true),
        record_id: Some(record.record_id),
        status: None,
        data: None,
    }
}

fn allowed_record_response(message: &str, allowed: bool, record: TypedRecord) -> DaemonResponse {
    DaemonResponse {
        ok: true,
        message: message.to_string(),
        allowed: Some(allowed),
        record_id: Some(record.record_id),
        status: None,
        data: None,
    }
}

fn write_response(stream: &mut UnixStream, response: &DaemonResponse) -> io::Result<()> {
    let body = serde_json::to_string(response).map_err(io_other)?;
    stream.write_all(body.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()
}

fn bootstrap_sandbox_audit(state: &SharedState) -> io::Result<()> {
    match hooks::on_sandbox_audit("aegxd", "daemon-bootstrap") {
        Ok((audit, _record)) => {
            let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
            if audit.compliance != sandbox_audit::SandboxCompliance::Full {
                guard
                    .degraded_reasons
                    .push(format!("sandbox compliance is {:?}", audit.compliance));
            }
            guard.sandbox_audit = Some(audit);
            Ok(())
        }
        Err(e) => {
            let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
            guard
                .degraded_reasons
                .push(format!("sandbox audit failed at startup: {e}"));
            Ok(())
        }
    }
}

fn emit_heartbeat_record(agent_id: &str, session_id: &str) -> io::Result<TypedRecord> {
    let mut meta = RecordMeta::now();
    meta.agent_id = Some(agent_id.to_string());
    meta.session_id = Some(session_id.to_string());
    meta.channel = Some("daemon".to_string());

    let payload = json!({
        "event": "daemon_heartbeat",
        "agent_id": agent_id,
        "session_id": session_id,
        "ts": Utc::now().to_rfc3339(),
    });

    let record = records::emit_record(
        RecordType::SessionMessage,
        Principal::Sys,
        TaintFlags::empty(),
        vec![],
        meta,
        payload,
    )?;
    audit_chain::emit_audit(&record.record_id)?;
    Ok(record)
}

fn push_unique_reason(reasons: &mut Vec<String>, reason: impl Into<String>) {
    let reason = reason.into();
    if reasons.iter().any(|existing| existing == &reason) {
        return;
    }
    reasons.push(reason);
    while reasons.len() > MAX_DEGRADED_REASONS {
        reasons.remove(0);
    }
}

fn remember_degraded_reason(state: &SharedState, reason: impl Into<String>) {
    let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
    push_unique_reason(&mut guard.degraded_reasons, reason);
}

fn note_bypass_attempt(state: &SharedState, reason: impl Into<String>, target: &str) {
    let reason = reason.into();
    let attempt_count = {
        let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
        guard.bypass_attempt_count += 1;
        guard.last_bypass_attempt_at = Some(Utc::now());
        push_unique_reason(
            &mut guard.degraded_reasons,
            "daemon IPC integrity violation observed",
        );
        guard.bypass_attempt_count
    };

    let summary = format!(
        "Daemon bypass attempt detected: {} (attempt #{attempt_count}).",
        reason
    );
    let _ = emit_runtime_signal(
        ThreatCategory::DaemonBypassAttempt,
        AlertSeverity::Critical,
        summary,
        "daemon-bypass-detected",
        target,
        true,
        Some("Inspect local processes reaching the daemon socket, rotate the daemon auth token, and restart the daemon if compromise is suspected."),
    );
}

fn emit_runtime_event_record(
    rule_id: &str,
    summary: &str,
    target: &str,
    blocked: bool,
) -> io::Result<TypedRecord> {
    let mut meta = RecordMeta::now();
    meta.channel = Some("daemon".to_string());
    meta.tool_id = Some("aegxd".to_string());
    meta.config_key = Some(target.to_string());
    meta.rule_id = Some(rule_id.to_string());

    let payload = json!({
        "event": rule_id,
        "summary": summary,
        "target": target,
        "blocked": blocked,
        "ts": Utc::now().to_rfc3339(),
    });

    let record = records::emit_record(
        RecordType::ToolResult,
        Principal::Sys,
        TaintFlags::empty(),
        vec![],
        meta,
        payload,
    )?;
    audit_chain::emit_audit(&record.record_id)?;
    Ok(record)
}

fn notification_level_for_alert(severity: AlertSeverity) -> NotificationLevel {
    match severity {
        AlertSeverity::Info => NotificationLevel::Info,
        AlertSeverity::Medium => NotificationLevel::Warning,
        AlertSeverity::High => NotificationLevel::Error,
        AlertSeverity::Critical => NotificationLevel::Critical,
    }
}

fn emit_runtime_signal(
    category: ThreatCategory,
    severity: AlertSeverity,
    summary: impl Into<String>,
    rule_id: &str,
    target: &str,
    blocked: bool,
    suggested_action: Option<&str>,
) -> io::Result<()> {
    let summary = summary.into();
    let record = emit_runtime_event_record(rule_id, &summary, target, blocked)?;
    let alert = alerts::emit_custom_alert(
        category,
        severity,
        summary,
        Principal::Sys,
        TaintFlags::empty(),
        None,
        rule_id,
        &record.record_id,
        target,
        blocked,
    )?;
    alerts::notify(
        notification_level_for_alert(alert.severity),
        NotificationSource::System,
        alert.summary.clone(),
        Some(&alert.record_id),
        suggested_action,
    );
    Ok(())
}

fn permissions_reason(path: &Path, label: &str, expected_mode: u32) -> Option<String> {
    match fs::metadata(path) {
        Ok(meta) => {
            let actual = meta.permissions().mode() & 0o777;
            if actual == expected_mode {
                None
            } else {
                Some(format!(
                    "{label} permissions are {:o}, expected {:o}",
                    actual, expected_mode
                ))
            }
        }
        Err(e) => Some(format!("failed to inspect {label}: {e}")),
    }
}

fn pid_file_reason(current_pid: u32) -> Option<String> {
    let path = config::daemon_pid_file();
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(e) => return Some(format!("failed to read daemon pid file: {e}")),
    };
    let parsed = match raw.trim().parse::<u32>() {
        Ok(pid) => pid,
        Err(e) => return Some(format!("daemon pid file is invalid: {e}")),
    };
    if parsed == current_pid {
        None
    } else {
        Some(format!(
            "daemon pid file reports {parsed}, expected current pid {current_pid}"
        ))
    }
}

fn auth_token_state() -> (bool, Option<String>) {
    let path = config::daemon_auth_token_file();
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(e) => return (false, Some(format!("failed to read daemon auth token: {e}"))),
    };
    if raw.trim().is_empty() {
        (false, Some("daemon auth token file is empty".to_string()))
    } else {
        (true, None)
    }
}

fn sync_degraded_signals(state: &SharedState, reasons: &[String]) {
    let new_reasons = {
        let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
        let new_reasons = reasons
            .iter()
            .filter(|reason| !guard.reported_degraded_reasons.iter().any(|seen| seen == *reason))
            .cloned()
            .collect::<Vec<_>>();
        guard.reported_degraded_reasons = reasons.to_vec();
        new_reasons
    };

    for reason in new_reasons {
        let _ = emit_runtime_signal(
            ThreatCategory::DaemonDegraded,
            AlertSeverity::High,
            format!("Daemon degraded mode detected: {reason}"),
            "daemon-degraded",
            "daemon_runtime",
            false,
            Some("Run `aegx status`, review degraded reasons, inspect runtime file permissions, and restart the daemon after remediation."),
        );
    }
}

fn build_status_snapshot(state: &SharedState) -> io::Result<DaemonStatusSnapshot> {
    let (
        started_at,
        heartbeat_count,
        events_processed,
        last_request_at,
        last_heartbeat_at,
        bypass_attempt_count,
        last_bypass_attempt_at,
        sandbox_audit_result,
        persistent_reasons,
    ) = {
        let guard = state.lock().unwrap_or_else(|e| e.into_inner());
        (
            guard.started_at,
            guard.heartbeat_count,
            guard.events_processed,
            guard.last_request_at,
            guard.last_heartbeat_at,
            guard.bypass_attempt_count,
            guard.last_bypass_attempt_at,
            guard.sandbox_audit.clone(),
            guard.degraded_reasons.clone(),
        )
    };

    let now = Utc::now();
    let current_pid = std::process::id();
    let policy_file = config::default_policy_file();
    let policy_sha256 = if policy_file.exists() {
        let bytes = fs::read(&policy_file)?;
        Some(sha256_hex(&bytes))
    } else {
        None
    };

    let (policy_loaded, policy_error) = match aegx_guard::guard::Guard::load_default() {
        Ok(_) => (true, None),
        Err(e) => (false, Some(e.to_string())),
    };

    let (audit_chain_valid, audit_chain_error) = match audit_chain::verify_chain()? {
        Ok(_) => (true, None),
        Err(e) => (false, Some(e.to_string())),
    };

    let mut degraded_reasons = persistent_reasons;
    if !policy_loaded {
        push_unique_reason(
            &mut degraded_reasons,
            policy_error
                .clone()
                .unwrap_or_else(|| "policy failed to load".to_string()),
        );
    }
    if !audit_chain_valid {
        push_unique_reason(
            &mut degraded_reasons,
            audit_chain_error
                .clone()
                .unwrap_or_else(|| "audit chain verification failed".to_string()),
        );
    }
    if let Some(reason) = permissions_reason(&config::runtime_dir(), "daemon runtime directory", 0o700)
    {
        push_unique_reason(&mut degraded_reasons, reason);
    }

    let socket_path = config::daemon_socket_file();
    if !socket_path.exists() {
        push_unique_reason(&mut degraded_reasons, "daemon socket is missing");
    } else if let Some(reason) = permissions_reason(&socket_path, "daemon socket", 0o600) {
        push_unique_reason(&mut degraded_reasons, reason);
    }

    if let Some(reason) = pid_file_reason(current_pid) {
        push_unique_reason(&mut degraded_reasons, reason);
    }
    if let Some(reason) = permissions_reason(&config::daemon_pid_file(), "daemon pid file", 0o600) {
        push_unique_reason(&mut degraded_reasons, reason);
    }

    let (auth_token_present, auth_token_reason) = auth_token_state();
    if let Some(reason) = auth_token_reason {
        push_unique_reason(&mut degraded_reasons, reason);
    }
    if auth_token_present {
        if let Some(reason) =
            permissions_reason(&config::daemon_auth_token_file(), "daemon auth token", 0o600)
        {
            push_unique_reason(&mut degraded_reasons, reason);
        }
    }

    let heartbeat_stale = match last_heartbeat_at {
        Some(ts) => (now - ts).num_seconds() > HEARTBEAT_STALE_SECS,
        None => (now - started_at).num_seconds() > HEARTBEAT_STALE_SECS,
    };
    if heartbeat_stale {
        match last_heartbeat_at {
            Some(ts) => push_unique_reason(
                &mut degraded_reasons,
                format!(
                    "daemon heartbeat is stale: last heartbeat at {}",
                    ts.to_rfc3339()
                ),
            ),
            None => push_unique_reason(
                &mut degraded_reasons,
                format!(
                    "daemon has not received a heartbeat within {} seconds of startup",
                    HEARTBEAT_STALE_SECS
                ),
            ),
        }
    }

    if bypass_attempt_count > 0 {
        push_unique_reason(
            &mut degraded_reasons,
            format!("{bypass_attempt_count} daemon bypass attempt(s) detected"),
        );
    }

    if let Some(ref audit) = sandbox_audit_result {
        if audit.compliance != sandbox_audit::SandboxCompliance::Full {
            push_unique_reason(
                &mut degraded_reasons,
                format!("sandbox compliance is {:?}", audit.compliance),
            );
        }
    }

    Ok(DaemonStatusSnapshot {
        status_version: "0.1".to_string(),
        pid: current_pid,
        started_at,
        uptime_seconds: (now - started_at).num_seconds().max(0) as u64,
        socket_path: socket_path.display().to_string(),
        initialized: config::aer_root().exists(),
        auth_token_present,
        policy_file: policy_file.display().to_string(),
        policy_sha256,
        policy_loaded,
        policy_error,
        record_count: records::record_count()?,
        alert_count: alerts::alert_count()?,
        audit_chain_valid,
        audit_chain_error,
        heartbeat_count,
        events_processed,
        last_request_at,
        last_heartbeat_at,
        heartbeat_stale,
        bypass_attempt_count,
        last_bypass_attempt_at,
        sandbox_audit: sandbox_audit_result,
        degraded_reasons,
    })
}

fn refresh_status_file(state: &SharedState) -> io::Result<()> {
    let mut snapshot = build_status_snapshot(state)?;
    sync_degraded_signals(state, &snapshot.degraded_reasons);
    snapshot = build_status_snapshot(state)?;

    let path = config::daemon_status_file();
    let body = serde_json::to_string_pretty(&snapshot).map_err(io_other)?;
    fs::write(&path, body)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn secure_runtime_dir() -> io::Result<()> {
    let dir = config::runtime_dir();
    fs::create_dir_all(&dir)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn ensure_auth_token() -> io::Result<String> {
    let path = config::daemon_auth_token_file();
    if path.exists() {
        let token = fs::read_to_string(&path)?;
        return Ok(token.trim().to_string());
    }

    let token = format!("aegxd-{}", Uuid::new_v4());
    fs::write(&path, format!("{}\n", token))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    Ok(token)
}

fn io_other<E: std::fmt::Display>(err: E) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    static TEST_ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn auth_token_roundtrip() {
        let _lock = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempdir().unwrap();
        std::env::set_var("PRV_STATE_DIR", dir.path());
        secure_runtime_dir().unwrap();
        let token = ensure_auth_token().unwrap();
        assert!(token.starts_with("aegxd-"));
        let reread = read_auth_token().unwrap();
        assert_eq!(token, reread);
        std::env::remove_var("PRV_STATE_DIR");
    }

    #[test]
    fn status_file_roundtrip() {
        let _lock = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempdir().unwrap();
        std::env::set_var("PRV_STATE_DIR", dir.path());
        config::ensure_aer_dirs().unwrap();
        secure_runtime_dir().unwrap();
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        refresh_status_file(&state).unwrap();
        let status = read_status_file().unwrap();
        assert_eq!(status.status_version, "0.1");
        std::env::remove_var("PRV_STATE_DIR");
    }
}
