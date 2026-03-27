#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
dist_dir="${DIST_DIR:-${repo_root}/dist}"
results_dir="${RESULTS_DIR:-${repo_root}/results}"
bundle_version=""
build_release="1"

usage() {
  cat <<'EOF'
Usage: package_skill.sh [--bundle-version <value>] [--dist-dir <path>] [--results-dir <path>] [--no-build]

Builds a distributable Provenable skill bundle containing:
- SKILL.md and AGENT.md
- release binaries (aegx, aegxd)
- integration adapters for OpenClaw, Manus, and Claude Code
- core operator documentation
- installer entrypoints and smoke-test helpers
- a bundle manifest with per-file SHA-256 digests
- a top-level checksums.txt and compressed tar.gz archive
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bundle-version)
      bundle_version="${2:?missing bundle version}"
      shift 2
      ;;
    --dist-dir)
      dist_dir="${2:?missing dist dir}"
      shift 2
      ;;
    --results-dir)
      results_dir="${2:?missing results dir}"
      shift 2
      ;;
    --no-build)
      build_release="0"
      shift
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

if [[ -z "${bundle_version}" ]]; then
  if git -C "${repo_root}" rev-parse --git-dir >/dev/null 2>&1; then
    bundle_version="$(git -C "${repo_root}" describe --tags --always 2>/dev/null || git -C "${repo_root}" rev-parse --short HEAD)"
  else
    bundle_version="$(date -u +%Y%m%dT%H%M%SZ)"
  fi
fi

bundle_name="provenable-skill-${bundle_version}"
stage_dir="${dist_dir}/${bundle_name}"
archive_path="${dist_dir}/${bundle_name}.tar.gz"
manifest_path="${stage_dir}/skill-bundle-manifest.json"
checksums_path="${stage_dir}/checksums.txt"
summary_path="${results_dir}/skill_bundle_latest.json"

aegx_bin="${repo_root}/target/release/aegx"
aegxd_bin="${repo_root}/target/release/aegxd"

echo "[package-skill] repo root: ${repo_root}"
echo "[package-skill] bundle name: ${bundle_name}"
mkdir -p "${dist_dir}" "${results_dir}"
rm -rf "${stage_dir}" "${archive_path}"

if [[ "${build_release}" == "1" ]]; then
  echo "[package-skill] building release workspace"
  (
    cd "${repo_root}"
    cargo build --workspace --release
  )
fi

for required_bin in "${aegx_bin}" "${aegxd_bin}"; do
  if [[ ! -x "${required_bin}" ]]; then
    printf '[package-skill] missing required executable: %s\n' "${required_bin}" >&2
    exit 1
  fi
done

mkdir -p \
  "${stage_dir}/bin" \
  "${stage_dir}/docs" \
  "${stage_dir}/examples" \
  "${stage_dir}/integrations" \
  "${stage_dir}/installer/docs" \
  "${stage_dir}/installer/install" \
  "${stage_dir}/installer/manifest" \
  "${stage_dir}/installer/scripts" \
  "${stage_dir}/schemas"

copy_rel() {
  local rel="$1"
  local src="${repo_root}/${rel}"
  local dst_parent="${stage_dir}/$(dirname "${rel}")"
  if [[ ! -e "${src}" ]]; then
    printf '[package-skill] required path not found: %s\n' "${src}" >&2
    exit 1
  fi
  mkdir -p "${dst_parent}"
  cp -R "${src}" "${dst_parent}/"
}

for rel in \
  SKILL.md \
  AGENT.md \
  README.md \
  LICENSE \
  NOTICE \
  Makefile \
  docs/AGENT_INTEGRATION.md \
  docs/BUNDLE_FORMAT_GUIDE.md \
  docs/CLI_REFERENCE.md \
  docs/HARDENING_BASELINE_AUDIT.md \
  docs/INSTALL.md \
  docs/QUICKSTART.md \
  docs/THREAT_MODEL.md \
  docs/TROUBLESHOOTING.md \
  docs/VERIFICATION_GUIDE.md \
  examples/quickstart.sh \
  installer/README.md \
  installer/checksums.txt \
  installer/docs/INSTALLER_DOCS.md \
  installer/install/install-proven-aer.ps1 \
  installer/install/install-proven-aer.sh \
  installer/manifest/manifest.json \
  installer/scripts/smoke_install_unix.sh \
  installer/scripts/smoke_install_windows.ps1 \
  schemas/aegx-schemas.json; do
  copy_rel "${rel}"
done

cp "${aegx_bin}" "${stage_dir}/bin/aegx"
cp "${aegxd_bin}" "${stage_dir}/bin/aegxd"
cp -R "${repo_root}/integrations/." "${stage_dir}/integrations/"

export STAGE_DIR="${stage_dir}"
export BUNDLE_NAME="${bundle_name}"
export BUNDLE_VERSION="${bundle_version}"
export REPO_ROOT="${repo_root}"
python3 <<'PY'
import datetime as dt
import hashlib
import json
import os
import pathlib
import subprocess

stage = pathlib.Path(os.environ["STAGE_DIR"])
repo_root = pathlib.Path(os.environ["REPO_ROOT"])
manifest_path = stage / "skill-bundle-manifest.json"


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

files = []
for path in sorted(p for p in stage.rglob("*") if p.is_file()):
    rel = path.relative_to(stage).as_posix()
    files.append(
        {
            "path": rel,
            "sha256": sha256_file(path),
            "size_bytes": path.stat().st_size,
        }
    )

try:
    git_commit = subprocess.check_output(
        ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
        text=True,
    ).strip()
except Exception:
    git_commit = None

manifest = {
    "schema_version": "0.1",
    "bundle_name": os.environ["BUNDLE_NAME"],
    "bundle_version": os.environ["BUNDLE_VERSION"],
    "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    "git_commit": git_commit,
    "entrypoints": {
        "skill_manifest": "SKILL.md",
        "agent_manifest": "AGENT.md",
        "primary_cli": "bin/aegx",
        "daemon_cli": "bin/aegxd",
        "openclaw_adapter": "integrations/openclaw/openclaw_adapter.sh",
        "manus_adapter": "integrations/manus/manus_adapter.sh",
        "claude_code_adapter": "integrations/claude-code/claude_code_adapter.sh",
    },
    "security_contract": {
        "requires_authenticated_daemon": True,
        "requires_live_self_verification": True,
        "requires_degraded_mode_reporting": True,
        "requires_snapshot_before_risky_change": True,
    },
    "artifacts": files,
}
manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
PY

(
  cd "${stage_dir}"
  find . -type f ! -name 'checksums.txt' -print0 \
    | sort -z \
    | xargs -0 sha256sum > "${checksums_path}"
)

tar -C "${dist_dir}" -czf "${archive_path}" "${bundle_name}"

archive_sha256="$(sha256sum "${archive_path}" | awk '{print $1}')"
cat > "${summary_path}" <<EOF
{
  "bundle_name": "${bundle_name}",
  "bundle_version": "${bundle_version}",
  "stage_dir": "${stage_dir}",
  "archive_path": "${archive_path}",
  "archive_sha256": "${archive_sha256}",
  "manifest_path": "${manifest_path}",
  "checksums_path": "${checksums_path}"
}
EOF

echo "[package-skill] stage dir: ${stage_dir}"
echo "[package-skill] archive: ${archive_path}"
echo "[package-skill] archive sha256: ${archive_sha256}"
echo "[package-skill] summary: ${summary_path}"
