#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../common/aegx_platform_common.sh
source "${script_dir}/../common/aegx_platform_common.sh"

CLAUDE_AGENT_ID="${CLAUDE_AGENT_ID:-claude-code}"
CLAUDE_SESSION_ID="${CLAUDE_SESSION_ID:-${1:-default}}"
CLAUDE_MODE="${CLAUDE_MODE:-before-session}"

run_before_session() {
  full_adapter_bootstrap
  emit_heartbeat "${CLAUDE_AGENT_ID}" "${CLAUDE_SESSION_ID}"
  preflight_guard_status
  cat <<'EOF'
Claude Code session-start contract:
1. Keep `aegxd` running for the duration of the coding session.
2. Treat degraded daemon state as a hard stop for risky repository mutations.
3. Use `aegx prove --json` and `aegx self-verify --json` before major edits or tool-driven refactors.
EOF
}

run_before_refactor() {
  full_adapter_bootstrap
  snapshot_before_risky_change "claude-refactor-${CLAUDE_SESSION_ID}"
  emit_heartbeat "${CLAUDE_AGENT_ID}" "${CLAUDE_SESSION_ID}"
  active_preflight_guard_status
  print_degraded_mode_statement
}

run_after_tool_burst() {
  full_adapter_bootstrap
  emit_heartbeat "${CLAUDE_AGENT_ID}" "${CLAUDE_SESSION_ID}"
  "${AEGX_BIN}" daemon status
}

run_after_incident() {
  full_adapter_bootstrap
  export_bundle_to_dir
  print_degraded_mode_statement
}

case "${CLAUDE_MODE}" in
  before-session)
    run_before_session
    ;;
  before-refactor)
    run_before_refactor
    ;;
  after-tool-burst)
    run_after_tool_burst
    ;;
  after-incident)
    run_after_incident
    ;;
  *)
    cat >&2 <<EOF
Unknown CLAUDE_MODE='${CLAUDE_MODE}'.
Use one of: before-session, before-refactor, after-tool-burst, after-incident.
EOF
    exit 2
    ;;
esac
