#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../common/aegx_platform_common.sh
source "${script_dir}/../common/aegx_platform_common.sh"

OPENCLAW_AGENT_ID="${OPENCLAW_AGENT_ID:-openclaw}"
OPENCLAW_SESSION_ID="${OPENCLAW_SESSION_ID:-${1:-default}}"
OPENCLAW_MODE="${OPENCLAW_MODE:-preflight}"

run_preflight() {
  full_adapter_bootstrap
  emit_heartbeat "${OPENCLAW_AGENT_ID}" "${OPENCLAW_SESSION_ID}"
  active_preflight_guard_status
  print_degraded_mode_statement
}

run_before_skill_install() {
  full_adapter_bootstrap
  snapshot_before_risky_change "openclaw-skill-install-${OPENCLAW_SESSION_ID}"
  emit_heartbeat "${OPENCLAW_AGENT_ID}" "${OPENCLAW_SESSION_ID}"
  print_degraded_mode_statement
  cat <<'EOF'
OpenClaw skill-install gate:
1. Route skill package verification through the AEGX skill-install hook path.
2. Refuse installation if self-verification or daemon status is degraded.
3. Keep the generated snapshot so rollback remains available if later evidence shows compromise.
EOF
}

run_before_agent_turn() {
  full_adapter_bootstrap
  emit_heartbeat "${OPENCLAW_AGENT_ID}" "${OPENCLAW_SESSION_ID}"
  preflight_guard_status
}

run_after_incident() {
  full_adapter_bootstrap
  export_bundle_to_dir
}

case "${OPENCLAW_MODE}" in
  preflight)
    run_preflight
    ;;
  before-skill-install)
    run_before_skill_install
    ;;
  before-agent-turn)
    run_before_agent_turn
    ;;
  after-incident)
    run_after_incident
    ;;
  *)
    cat >&2 <<EOF
Unknown OPENCLAW_MODE='${OPENCLAW_MODE}'.
Use one of: preflight, before-skill-install, before-agent-turn, after-incident.
EOF
    exit 2
    ;;
esac
