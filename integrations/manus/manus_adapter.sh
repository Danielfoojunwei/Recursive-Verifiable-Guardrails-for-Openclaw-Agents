#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../common/aegx_platform_common.sh
source "${script_dir}/../common/aegx_platform_common.sh"

MANUS_AGENT_ID="${MANUS_AGENT_ID:-manus}"
MANUS_SESSION_ID="${MANUS_SESSION_ID:-${1:-default}}"
MANUS_MODE="${MANUS_MODE:-before-task}"

run_before_task() {
  full_adapter_bootstrap
  emit_heartbeat "${MANUS_AGENT_ID}" "${MANUS_SESSION_ID}"
  preflight_guard_status
  cat <<'EOF'
Manus task-start contract:
1. Run `aegx prove --json` before risky work and inspect active alerts.
2. Keep aegxd alive for the full task so degraded state remains observable.
3. Route persistent memory writes and sensitive reads through guarded hook surfaces whenever a host wrapper exists.
EOF
}

run_before_destructive_action() {
  full_adapter_bootstrap
  snapshot_before_risky_change "manus-risky-${MANUS_SESSION_ID}"
  emit_heartbeat "${MANUS_AGENT_ID}" "${MANUS_SESSION_ID}"
  active_preflight_guard_status
  print_degraded_mode_statement
}

run_after_turn() {
  full_adapter_bootstrap
  emit_heartbeat "${MANUS_AGENT_ID}" "${MANUS_SESSION_ID}"
  "${AEGX_BIN}" prove --json
}

run_after_incident() {
  full_adapter_bootstrap
  export_bundle_to_dir
  print_degraded_mode_statement
}

case "${MANUS_MODE}" in
  before-task)
    run_before_task
    ;;
  before-destructive-action)
    run_before_destructive_action
    ;;
  after-turn)
    run_after_turn
    ;;
  after-incident)
    run_after_incident
    ;;
  *)
    cat >&2 <<EOF
Unknown MANUS_MODE='${MANUS_MODE}'.
Use one of: before-task, before-destructive-action, after-turn, after-incident.
EOF
    exit 2
    ;;
esac
