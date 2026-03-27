#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: validate_skill_bundle.sh --bundle <bundle-dir-or-tarball> [--results-dir <path>]

Validates a packaged Provenable skill bundle by checking:
- required top-level files and platform adapters
- SHA-256 checksums in checksums.txt
- JSON structure of skill-bundle-manifest.json
- shell syntax for adapter scripts
- CLI entrypoints validate cleanly (`aegx --help`, `aegx daemon --help`, executable `aegxd`)
- packaged OpenClaw, Manus, and Claude adapters execute successfully using bundled binaries

Writes a JSON validation summary to results/skill_bundle_validation_latest.json.
EOF
}

bundle_path=""
results_dir=""
work_dir=""
cleanup_needed="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bundle)
      bundle_path="${2:?missing bundle path}"
      shift 2
      ;;
    --results-dir)
      results_dir="${2:?missing results dir}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'Unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "${bundle_path}" ]]; then
  printf 'Missing required --bundle argument\n' >&2
  usage >&2
  exit 2
fi

bundle_path="$(python3 - "$bundle_path" <<'PY'
import os, sys
print(os.path.abspath(sys.argv[1]))
PY
)"

if [[ ! -e "${bundle_path}" ]]; then
  printf 'Bundle path not found: %s\n' "${bundle_path}" >&2
  exit 1
fi

if [[ -z "${results_dir}" ]]; then
  if [[ -d "$(dirname "${bundle_path}")/../results" ]]; then
    results_dir="$(cd "$(dirname "${bundle_path}")/../results" && pwd)"
  else
    results_dir="$(pwd)/results"
  fi
fi
mkdir -p "${results_dir}"
summary_path="${results_dir}/skill_bundle_validation_latest.json"

if [[ -d "${bundle_path}" ]]; then
  stage_dir="${bundle_path}"
else
  work_dir="$(mktemp -d)"
  cleanup_needed="1"
  tar -C "${work_dir}" -xzf "${bundle_path}"
  extracted_count="$(find "${work_dir}" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
  if [[ "${extracted_count}" != "1" ]]; then
    printf 'Expected tarball to contain exactly one top-level directory, found %s\n' "${extracted_count}" >&2
    exit 1
  fi
  stage_dir="$(find "${work_dir}" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
fi

trap 'if [[ "${cleanup_needed}" == "1" && -n "${work_dir}" && -d "${work_dir}" ]]; then rm -rf "${work_dir}"; fi' EXIT

required_paths=(
  "SKILL.md"
  "AGENT.md"
  "README.md"
  "bin/aegx"
  "bin/aegxd"
  "integrations/common/aegx_platform_common.sh"
  "integrations/openclaw/openclaw_adapter.sh"
  "integrations/manus/manus_adapter.sh"
  "integrations/claude-code/claude_code_adapter.sh"
  "skill-bundle-manifest.json"
  "checksums.txt"
)

missing=()
for rel in "${required_paths[@]}"; do
  if [[ ! -e "${stage_dir}/${rel}" ]]; then
    missing+=("${rel}")
  fi
done

if [[ ${#missing[@]} -gt 0 ]]; then
  printf 'Missing required bundle paths:\n' >&2
  printf '  - %s\n' "${missing[@]}" >&2
  exit 1
fi

(
  cd "${stage_dir}"
  sha256sum -c checksums.txt
) >/tmp/provenable_skill_checksum_check.log 2>&1
checksum_ok="true"
if ! grep -q ': OK' /tmp/provenable_skill_checksum_check.log; then
  checksum_ok="false"
fi
if grep -q ': FAILED' /tmp/provenable_skill_checksum_check.log; then
  checksum_ok="false"
fi
if [[ "${checksum_ok}" != "true" ]]; then
  cat /tmp/provenable_skill_checksum_check.log >&2
  exit 1
fi

python3 - "${stage_dir}/skill-bundle-manifest.json" <<'PY' >/tmp/provenable_skill_manifest_check.json
import json
import pathlib
import sys

manifest_path = pathlib.Path(sys.argv[1])
manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
required_entrypoints = {
    'skill_manifest',
    'agent_manifest',
    'primary_cli',
    'daemon_cli',
    'openclaw_adapter',
    'manus_adapter',
    'claude_code_adapter',
}
missing = sorted(required_entrypoints - set(manifest.get('entrypoints', {}).keys()))
if manifest.get('schema_version') != '0.1':
    raise SystemExit('unexpected schema_version')
if missing:
    raise SystemExit('missing entrypoints: ' + ', '.join(missing))
print(json.dumps({
    'bundle_name': manifest.get('bundle_name'),
    'bundle_version': manifest.get('bundle_version'),
    'artifact_count': len(manifest.get('artifacts', [])),
    'entrypoints': manifest.get('entrypoints', {}),
}, indent=2))
PY

bash -n "${stage_dir}/integrations/common/aegx_platform_common.sh"
bash -n "${stage_dir}/integrations/openclaw/openclaw_adapter.sh"
bash -n "${stage_dir}/integrations/manus/manus_adapter.sh"
bash -n "${stage_dir}/integrations/claude-code/claude_code_adapter.sh"

test -x "${stage_dir}/bin/aegxd"
"${stage_dir}/bin/aegx" --help >/tmp/provenable_skill_aegx_help.txt
"${stage_dir}/bin/aegx" daemon --help >/tmp/provenable_skill_aegx_daemon_help.txt

run_adapter_smoke_test() {
  local adapter_name="$1"
  local mode_var="$2"
  local mode_value="$3"
  local script_path="$4"
  local scratch_root
  scratch_root="$(mktemp -d "/tmp/provenable-skill-${adapter_name}-XXXXXX")"
  local home_dir="${scratch_root}/home"
  local log_dir="${stage_dir}/.validation-logs/${adapter_name}"
  rm -rf "${log_dir}"
  mkdir -p "${home_dir}" "${log_dir}"
  (
    export HOME="${home_dir}"
    export AEGX_REPO_ROOT="${stage_dir}"
    unset PRV_STATE_DIR
    unset AEGX_INTEGRATION_LOG_DIR
    export "${mode_var}=${mode_value}"
    bash "${script_path}" "validation-${adapter_name}" >"${log_dir}/adapter-run.log" 2>&1
    "${stage_dir}/bin/aegx" daemon stop >>"${log_dir}/adapter-run.log" 2>&1 || true
  )
  rm -rf "${scratch_root}"
}

run_adapter_smoke_test "openclaw" "OPENCLAW_MODE" "preflight" "${stage_dir}/integrations/openclaw/openclaw_adapter.sh"
run_adapter_smoke_test "manus" "MANUS_MODE" "before-task" "${stage_dir}/integrations/manus/manus_adapter.sh"
run_adapter_smoke_test "claude-code" "CLAUDE_MODE" "before-session" "${stage_dir}/integrations/claude-code/claude_code_adapter.sh"

python3 - "${summary_path}" "${stage_dir}" "/tmp/provenable_skill_manifest_check.json" <<'PY'
import datetime as dt
import json
import pathlib
import sys

summary_path = pathlib.Path(sys.argv[1])
stage_dir = pathlib.Path(sys.argv[2])
manifest_summary_path = pathlib.Path(sys.argv[3])
summary = {
    'generated_at': dt.datetime.now(dt.timezone.utc).isoformat(),
    'bundle_dir': str(stage_dir),
    'overall_ok': True,
    'checks': [
        {'name': 'required_paths_present', 'passed': True},
        {'name': 'checksums_verified', 'passed': True},
        {'name': 'manifest_schema_valid', 'passed': True},
        {'name': 'adapter_shell_syntax', 'passed': True},
        {'name': 'aegx_help_invocation', 'passed': True},
        {'name': 'aegx_daemon_help_invocation', 'passed': True},
        {'name': 'aegxd_executable_present', 'passed': True},
        {'name': 'openclaw_adapter_smoke_test', 'passed': True},
        {'name': 'manus_adapter_smoke_test', 'passed': True},
        {'name': 'claude_code_adapter_smoke_test', 'passed': True},
    ],
    'manifest_summary': json.loads(manifest_summary_path.read_text(encoding='utf-8')),
}
summary_path.write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
print(json.dumps(summary, indent=2))
PY

printf 'Validation summary written to %s\n' "${summary_path}"
