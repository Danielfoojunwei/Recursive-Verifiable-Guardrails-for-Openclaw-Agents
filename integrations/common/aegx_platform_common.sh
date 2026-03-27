#!/usr/bin/env bash
# Shared helper functions for concrete AEGX platform adapters.
# This library is intentionally shell-only so OpenClaw, Manus, and Claude Code
# wrappers can reuse the same operational path without extra dependencies.

if [[ -n "${AEGX_PLATFORM_COMMON_SH_LOADED:-}" ]]; then
  return 0
fi
AEGX_PLATFORM_COMMON_SH_LOADED=1

_aegx_common_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_AEGX_REPO_ROOT="$(cd "${_aegx_common_dir}/../.." && pwd)"

export AEGX_REPO_ROOT="${AEGX_REPO_ROOT:-${_AEGX_REPO_ROOT}}"

_default_aegx_bin="${AEGX_REPO_ROOT}/bin/aegx"
_default_aegxd_bin="${AEGX_REPO_ROOT}/bin/aegxd"
if [[ ! -x "${_default_aegx_bin}" ]]; then
  _default_aegx_bin="${AEGX_REPO_ROOT}/target/release/aegx"
fi
if [[ ! -x "${_default_aegxd_bin}" ]]; then
  _default_aegxd_bin="${AEGX_REPO_ROOT}/target/release/aegxd"
fi

_aegx_state_hash="$(printf '%s' "${AEGX_REPO_ROOT}" | sha256sum | awk '{print substr($1,1,12)}')"
_default_state_home="${HOME:-${AEGX_REPO_ROOT}}"
_default_state_dir="${_default_state_home}/.provenable/aegx-${_aegx_state_hash}"

export AEGX_BIN="${AEGX_BIN:-${_default_aegx_bin}}"
export AEGXD_BIN="${AEGXD_BIN:-${_default_aegxd_bin}}"
export PRV_STATE_DIR="${PRV_STATE_DIR:-${_default_state_dir}}"
export AEGX_INTEGRATION_LOG_DIR="${AEGX_INTEGRATION_LOG_DIR:-${PRV_STATE_DIR}/logs}"

_aegx_note() {
  printf '[aegx-adapter] %s\n' "$*"
}

_aegx_fail() {
  printf '[aegx-adapter] ERROR: %s\n' "$*" >&2
  return 1
}

ensure_log_dir() {
  mkdir -p "${AEGX_INTEGRATION_LOG_DIR}"
}

run_logged_guard_check() {
  local log_path="$1"
  shift
  if "$@" | tee "${log_path}"; then
    return 0
  fi
  local rc=$?
  _aegx_note "Guard check reported degraded or non-ideal state (exit ${rc}); see ${log_path}."
  return 0
}

validate_runtime_path_lengths() {
  local socket_path="${PRV_STATE_DIR}/.aer/runtime/aegxd.sock"
  if (( ${#socket_path} > 100 )); then
    _aegx_fail "PRV_STATE_DIR resolves to a daemon socket path that is too long for Unix IPC (${#socket_path} chars): ${socket_path}. Set a shorter PRV_STATE_DIR before running the adapter."
  fi
}

build_release_if_needed() {
  if [[ -x "${AEGX_BIN}" && -x "${AEGXD_BIN}" ]]; then
    return 0
  fi

  if [[ -f "${AEGX_REPO_ROOT}/Cargo.toml" ]]; then
    _aegx_note "Building release binaries because aegx/aegxd are not available yet."
    (
      cd "${AEGX_REPO_ROOT}"
      cargo build --workspace --release
    )
    return 0
  fi

  _aegx_fail "Neither bundled binaries nor a buildable Cargo workspace were found under ${AEGX_REPO_ROOT}."
}

init_if_needed() {
  mkdir -p "${PRV_STATE_DIR}"
  if [[ -d "${PRV_STATE_DIR}/.aer" ]]; then
    return 0
  fi

  _aegx_note "Initializing AEGX state at ${PRV_STATE_DIR}."
  "${AEGX_BIN}" init
}

ensure_daemon_running() {
  if "${AEGX_BIN}" daemon ping >/dev/null 2>&1; then
    return 0
  fi

  _aegx_note "Starting aegxd background daemon."
  "${AEGX_BIN}" daemon start >/dev/null
}

preflight_guard_status() {
  ensure_log_dir
  local stamp
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"

  _aegx_note "Running guard preflight checks."
  run_logged_guard_check "${AEGX_INTEGRATION_LOG_DIR}/status-${stamp}.log" "${AEGX_BIN}" status
  run_logged_guard_check "${AEGX_INTEGRATION_LOG_DIR}/daemon-status-${stamp}.log" "${AEGX_BIN}" daemon status
  run_logged_guard_check "${AEGX_INTEGRATION_LOG_DIR}/self-verify-${stamp}.json" "${AEGX_BIN}" self-verify --json
}

active_preflight_guard_status() {
  ensure_log_dir
  local stamp
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"

  _aegx_note "Running active guard preflight checks."
  run_logged_guard_check "${AEGX_INTEGRATION_LOG_DIR}/self-verify-active-${stamp}.json" "${AEGX_BIN}" self-verify --active --json
}

emit_heartbeat() {
  local agent_id="${1:-adapter}"
  local session_id="${2:-default}"
  _aegx_note "Emitting daemon heartbeat for agent=${agent_id} session=${session_id}."
  "${AEGX_BIN}" daemon heartbeat --agent-id "${agent_id}" --session-id "${session_id}"
}

snapshot_before_risky_change() {
  local snapshot_name="${1:-pre-risky-change}"
  _aegx_note "Creating snapshot ${snapshot_name}."
  "${AEGX_BIN}" snapshot create "${snapshot_name}" --scope full
}

export_bundle_to_dir() {
  ensure_log_dir
  local stamp
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  local log_path="${AEGX_INTEGRATION_LOG_DIR}/bundle-export-${stamp}.log"

  _aegx_note "Exporting evidence bundle."
  "${AEGX_BIN}" bundle export | tee "${log_path}"
}

full_adapter_bootstrap() {
  validate_runtime_path_lengths
  build_release_if_needed
  init_if_needed
  ensure_daemon_running
  preflight_guard_status
}

print_degraded_mode_statement() {
  cat <<'EOF'
Degraded-mode contract:
- If `aegx daemon status` shows unreachable daemon state, treat protection as degraded.
- If `aegx self-verify --active` reports failures, stop risky operations and escalate.
- If the adapter cannot emit a heartbeat, assume live coverage is not current.
- Do not bypass denied actions; choose a safer workflow or request user guidance.
EOF
}
