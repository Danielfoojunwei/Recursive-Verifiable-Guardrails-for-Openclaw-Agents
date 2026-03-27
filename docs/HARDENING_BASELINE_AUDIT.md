## Scope

This audit reviews the repository as cloned on 2026-03-27 and focuses on the real enforcement path in the current codebase, not aspirational documentation. The primary sources for this audit were `README.md`, `AGENT.md`, `SKILL.md`, `docs/CLI_REFERENCE.md`, `Cargo.toml`, `crates/aegx-runtime/src/hooks.rs`, `crates/aegx-runtime/src/prove.rs`, `crates/aegx-cli/src/cli.rs`, `crates/aegx-runtime/src/lib.rs`, and `crates/aegx-bundle/src/verify.rs`.

## Executive Baseline

The repository is currently a **strong CLI toolkit plus hook library**, not yet an unavoidable always-on runtime guardrail system. It contains real policy logic, real tamper-evident evidence recording, real rollback support, real bundle verification, and real guard decisions for control-plane, memory, conversation, file-read, network-egress, sandbox-audit, and skill-install surfaces. However, most runtime protections are only enforced when the host agent or integration layer **voluntarily routes operations through the provided hook functions**.

The current implementation does **not** yet provide a long-running daemon, mandatory runtime wrapper, Unix-socket IPC service, health heartbeat, watchdog, crash recovery loop, daemon authentication, replay-protected event transport, or live coverage verification of host-hook usage. The shipped command surface also lacks the requested operational commands such as `aegx self-check`, `aegx doctor`, `aegx daemon status`, and `aegx daemon verify-live`.

## 1. Which protections are truly enforced automatically today?

The following protections are genuinely automatic **once the corresponding runtime API or CLI path is invoked**.

| Surface | What is real today | Scope of automaticity | Evidence |
|---|---|---|---|
| Audit chain | Records are hash-linked and audit entries are emitted automatically whenever hook code emits records | Automatic inside the hook/record path only | `crates/aegx-runtime/src/hooks.rs`, `crates/aegx-records/*` |
| CPI guard | `on_control_plane_change()` evaluates control-plane requests, records decisions, emits alerts, and can trigger rollback policy handling | Automatic only if host routes control-plane changes through this chokepoint | `crates/aegx-runtime/src/hooks.rs` |
| MI write guard | `on_file_write()` guards recognized memory files, emits records, alerts, and rollback-policy input | Automatic only for writes routed through this hook or workspace helper | `crates/aegx-runtime/src/hooks.rs`, `crates/aegx-runtime/src/workspace.rs` |
| Conversation input guard | `on_message_input()` runs the injection scanner and records the result | Automatic only for inbound messages routed through this hook | `crates/aegx-runtime/src/hooks.rs` |
| Conversation output guard | `on_message_output()` runs leakage checks, emits contamination alerts, and feeds rollback policy | Automatic only for outbound text routed through this hook | `crates/aegx-runtime/src/hooks.rs` |
| Skill verification | `on_skill_install()` performs real package scanning and records the verification result | Automatic only if installation flows call this hook before enabling a skill | `crates/aegx-runtime/src/hooks.rs`, `crates/aegx-guard/src/skill_verifier.rs` |
| File-read decisions | `on_file_read()` performs real sensitivity checks and records allow/deny outcomes | Automatic only when reads are routed through the hook | `crates/aegx-runtime/src/hooks.rs` |
| Network-egress decisions | `on_outbound_request()` performs real URL/domain/payload checks and records allow/deny outcomes | Automatic only when requests are routed through the hook | `crates/aegx-runtime/src/hooks.rs` |
| Sandbox audit | `on_sandbox_audit()` performs a real environment inspection and records the result | Automatic only if called at session start by the host | `crates/aegx-runtime/src/hooks.rs` |
| Snapshot and rollback | `aegx snapshot`, `aegx rollback`, and rollback-policy functions perform real file-state operations | Automatic only for explicit CLI/API use and policy-triggered rollback paths that are already in-process | `crates/aegx-cli/src/cli.rs`, `crates/aegx-runtime/*` |
| Bundle verification | `aegx verify` and `verify_live()` perform real integrity validation over stored state/bundles | Automatic when those commands or functions are invoked | `crates/aegx-cli/src/cli.rs`, `crates/aegx-bundle/src/verify.rs` |

## 2. Which protections only work if the host agent voluntarily calls `aegx` at the correct times?

Almost all runtime guard surfaces currently depend on host cooperation.

| Protection area | Current dependency on host cooperation |
|---|---|
| Session lifecycle recording | Host must call session-start and message hooks |
| Control-plane enforcement | Host must route installs, config changes, tool registration, permission changes, and similar actions through `on_control_plane_change()` |
| Durable-memory enforcement | Host must route memory writes through `on_file_write()` or the workspace helper |
| Sensitive-file read protection | Host must route reads through `on_file_read()` |
| Network egress protection | Host must route requests through `on_outbound_request()` |
| Conversation scanning | Host must route both input and output through the conversation hooks |
| System prompt token registration | Host must call `on_system_prompt_available()` when the prompt becomes available |
| Sandbox audit | Host must invoke the sandbox audit at startup |
| Ongoing health review | Operator or host must call `aegx prove` / `aegx status`; there is no background supervisor |
| Skill/package scanning | Installer or agent must call the verifier before enabling a package |

The key architectural limitation is that the repo currently exposes **guard functions**, not an unavoidable chokepoint around the host runtime.

## 3. Which surfaces are documented as protected but are not yet protected by unavoidable interception or background supervision?

The current docs often describe protection at the level of the system, but the code enforces most of these claims only through opt-in integration.

| Documented/proposed protection | Actual current status |
|---|---|
| "Works with OpenClaw, Claude Code, Manus" | Documentation exists, but no concrete integration adapter directories or platform-specific wrappers are shipped |
| "Ready to use as a skill on any agent platform" | `SKILL.md` exists, but there is no packaging script, no generated `.skill` artifact path, no platform-specific install/test bundle, and no one-command validation flow |
| File read guard | Real policy exists, but no unavoidable interception of raw filesystem reads |
| Network egress monitor | Real policy exists, but no unavoidable interception of outbound traffic; no proxy, firewall, eBPF, or mandatory wrapper is shipped |
| Memory integrity for persistent memory | Real for guarded memory files routed through the workspace/hook path; not unavoidable for arbitrary direct writes outside that path |
| Control-plane protection | Real for control-plane operations sent through the CPI hook; not unavoidable if host mutates state directly |
| Always-on protection | Not implemented; there is no daemon, supervisor, heartbeat, watchdog, or required wrapper |
| Background health/liveness | Not implemented; status/prove are point-in-time commands over local state |
| Self-verifying runtime | Partially true only for local-state integrity verification; no live daemon synchronization, hook-coverage validation, or continuous runtime self-check loop |

## 4. What is the actual self-verification path today: bundle verification only, or live runtime self-checking too?

The current repository has **bundle verification plus limited live-state integrity verification**, but not live runtime self-verification in the stronger operational sense requested by the mission.

| Verification path | Exists today | What it actually checks |
|---|---|---|
| Exported bundle verification (`aegx verify`) | Yes | Record hashes, audit-chain integrity, blob integrity, manifest consistency |
| Live-state verification (`verify_live()` via `/prove`) | Yes | Local record-hash validity, blob integrity for referenced blobs, audit-chain continuity in the active state directory |
| Policy integrity during runtime | No continuous checker | Policy is loaded and used, but not continuously re-verified against a trusted manifest or signature during runtime |
| Binary integrity or version consistency | No | No shipped binary-integrity verification loop |
| Hook coverage verification | No | No mechanism proves that protected host operations are actually routed through the hooks |
| Daemon liveness/sync verification | No | No daemon exists |
| Heartbeat/watchdog verification | No | No heartbeat or watchdog exists |
| Installation/update provenance preservation | Partial at best | Skill package scanning exists, but there is no end-to-end trusted installation/update verification flow for shipped integration bundles |

Accordingly, the current system should be described as having **tamper-evident evidence verification** and **local-state integrity checking**, not a continuously self-verifying runtime guardrail fabric.

## 5. What is required to make OpenClaw, Manus, and Claude-style integration robust instead of aspirational?

Robust integration requires executable adapters and enforcement infrastructure, not only prose instructions.

First, the project needs a real always-on service, preferably `aegxd`, with local authenticated IPC, session registration, event submission, heartbeats, policy reload, liveness reporting, and crash recovery. Second, the host integration layer must move from advisory hook usage to **mandatory wrappers or enforced chokepoints** for file writes, sensitive reads, control-plane changes, network egress, and session I/O. Third, the system must detect when expected wrappers are missing and mark protection as degraded rather than silently assuming coverage.

In platform terms, each target environment needs its own concrete adapter directory with installation, startup, health check, smoke test, protected workflow example, and degraded-mode statement. The repo does not currently ship `integrations/openclaw/`, `integrations/manus/`, or `integrations/claude_cowork/`, so support for those platforms is presently documentation-led rather than implementation-led.

## 6. What currently exists for skill packaging, and what is missing for one-command import, validation, and smoke-test verification?

What exists today is the minimal skill-facing metadata surface: `SKILL.md`, `AGENT.md`, and some OpenClaw-oriented frontmatter. That is useful, but it is not yet a first-class packaging path.

| Packaging capability | Current status |
|---|---|
| Skill manifest (`SKILL.md`) | Exists |
| Agent guidance (`AGENT.md`) | Exists |
| OpenClaw metadata in frontmatter | Exists |
| Packaging script for distributable skill artifact | Missing |
| One-command bundle generation | Missing |
| Skill installation validator | Missing |
| Post-package self-test | Missing |
| Platform-specific packaging for Manus | Missing |
| Platform-specific packaging for Claude-style workflows | Missing |
| Import smoke tests across targets | Missing |
| `integrations/` directory with concrete adapters | Missing |
| `results/` artifacts for packaging validation | Missing |

## Command-Surface Gap

The current shipped CLI surface is limited to:

- `aegx init`
- `aegx snapshot create`
- `aegx snapshot list`
- `aegx rollback`
- `aegx bundle export`
- `aegx verify`
- `aegx report`
- `aegx prove`
- `aegx status`

The following required operational surfaces are not yet implemented:

- `aegx self-check`
- `aegx doctor`
- `aegx daemon status`
- `aegx daemon verify-live`
- daemon start/stop/install commands
- live health/heartbeat inspection
- degraded-mode reporting commands
- machine-readable coverage verification of host-hook enforcement

## Documentation Corrections Required

The docs should be tightened immediately to distinguish the following categories:

| Category | Correct current phrasing |
|---|---|
| Automatic inside current code paths | Hash-linked evidence, bundle verification, rollback logic, and guard decisions within invoked hook/API flows |
| Integration-dependent enforcement | CPI, MI, file-read, network-egress, conversation scanning, sandbox audit, and skill verification |
| Not yet implemented | Always-on daemon mode, unavoidable interception, live hook-coverage verification, daemon liveness checks, authenticated IPC, replay protection, first-class skill packaging, platform adapters |

## Concrete Gap Summary

The most important gap is not policy quality. It is **enforcement topology**. The repository already has meaningful guard logic, but it still trusts the host to remember to call it. To become an unavoidable guardrail system, the next implementation steps must prioritize:

1. a real background daemon and IPC path;
2. required host wrappers with fail-closed behavior where feasible;
3. explicit degraded-mode and bypass-detection records;
4. continuous self-verification of policy, daemon liveness, audit continuity, and coverage;
5. concrete, testable integration adapters for OpenClaw, Manus, and Claude-style workflows;
6. first-class skill packaging and smoke-test validation.

## Additional Implementation Notes

One operational blocker in the current sandbox is that the Rust toolchain is not presently available on `PATH`, so build-and-test validation cannot yet be executed until Rust is installed or made available. This does not change the audit findings above, but it will affect the implementation and validation phases.

## Bottom Line

At baseline, this repository is **not yet** an always-on guardrail runtime. It is a **credible guardrail library and CLI foundation** whose protections become real only when the host actually uses the provided chokepoints. The hardening work should therefore focus first on making enforcement persistent, supervised, difficult to bypass, and continuously self-verifying.
