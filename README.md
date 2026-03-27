# Provenable / AEGX

**Provenable / AEGX** is a hardened agent-security runtime and packaged skill system for operating autonomous workflows with verifiable guardrails, tamper-evident evidence, background daemon health monitoring, live self-verification, and platform adapters for **Manus**, **Claude Cowork / Claude Code**, **OpenClaw**, and related agent variants. In practical terms, it turns a set of formal guard surfaces into something an operator can actually run: a CLI, a daemon, a packageable bundle, and concrete integration scripts that can be dropped into an agent workflow and used immediately.[1] [2] [3] [4]

The system is designed to answer a simple operational problem: **how do you keep an agent useful while still making its risky behavior observable, provable, and recoverable?** AEGX answers that by combining guarded execution hooks, a continuously reachable daemon, authenticated IPC, live/passive self-checks, snapshot and rollback mechanics, evidence bundles, and platform-specific operating contracts. The result is not merely policy text; it is an executable control loop for agent safety.[1] [2] [5]

| Property | What it means in practice | Why it matters |
|---|---|---|
| **Always-on daemon** | `aegxd` runs in the background and exposes authenticated IPC for status, heartbeats, policy reloads, and runtime event handling. | Operators can see when protection is live, stale, or degraded instead of assuming it is active.[5] |
| **Live self-verification** | `aegx self-verify` checks runtime integrity, policy loading, daemon readiness, and active deny probes. | You can test whether enforcement is still working before a risky step.[5] |
| **Platform adapters** | Shipped wrappers encode step order for Manus, Claude Cowork / Claude Code, and OpenClaw. | Teams do not need to invent their own orchestration contract from scratch.[3] [6] [7] [8] |
| **First-class packaging** | The repository can be packaged into a distributable skill bundle with manifests, checksums, binaries, and adapters. | The whole system is portable and reusable, not tied to a single source checkout.[4] [9] |
| **Tamper-evident evidence** | Records and audit chain entries are hash-linked and exportable as bundles. | Incidents can be investigated and verified after the fact.[1] [5] |

## What the Hardened System Delivers

AEGX enforces a layered operating model. It protects **control-plane integrity**, **memory integrity**, **conversation / input safety**, **file-read safety**, **network egress safety**, **skill-install validation**, and **runtime status visibility**. If a platform wrapper exists, the intended flow is to bootstrap AEGX, keep the daemon alive, emit heartbeats around agent activity, run self-verification before risky actions, snapshot before high-risk mutations, and export an evidence bundle after incidents.[1] [2] [3] [5] [6] [7] [8]

| Capability | Operational outcome |
|---|---|
| **Control-plane protection** | Untrusted principals cannot safely change tools, skills, or permissions through the guarded path.[1] |
| **Memory integrity protection** | Persistent memory writes can be denied when provenance is tainted or untrusted.[1] |
| **Conversation / prompt-injection protection** | Suspicious agent inputs can be blocked before they become trusted state.[1] |
| **File-read protection** | Sensitive paths such as credential-like material can be denied through the guarded read surface.[1] |
| **Network egress protection** | Outbound destinations and payload characteristics can be evaluated before exfiltration occurs.[1] |
| **Snapshot and rollback** | Operators can create pre-change checkpoints and retain rollback options before refactors, destructive actions, or skill installs.[5] [6] [7] [8] |
| **Evidence export** | Bundles can be exported after incidents for later verification and reporting.[5] [6] [7] [8] |
| **Degraded-mode visibility** | The system explicitly surfaces daemon absence, stale heartbeats, policy problems, and sandbox-compliance caveats instead of hiding them.[5] [10] |

## How the System Operates

At runtime, AEGX uses a straightforward loop. First, the state directory is initialized and the default policy is loaded. Second, `aegxd` starts and publishes an authenticated IPC surface plus a persisted status snapshot. Third, host or adapter workflows emit heartbeats and request status or active verification before risky actions. Fourth, guarded events are evaluated and recorded into the evidence store. Fifth, operators inspect status, prove output, or self-verification results; if the system reports degraded mode, they stop risky work, choose a safer workflow, or escalate. Finally, if an incident occurs, they export an evidence bundle and, where appropriate, roll back to a known-good snapshot.[1] [5] [6] [7] [8]

> “If `aegx daemon status` shows unreachable daemon state, treat protection as degraded. If `aegx self-verify --active` reports failures, stop risky operations and escalate. If the adapter cannot emit a heartbeat, assume live coverage is not current. Do not bypass denied actions; choose a safer workflow or request user guidance.” — shared adapter degraded-mode contract.[3]

| Runtime component | Role |
|---|---|
| **`aegx`** | Operator CLI for init, status, daemon control, verification, snapshots, bundles, reports, and proof queries.[5] |
| **`aegxd`** | Background process that maintains live runtime status, IPC responsiveness, heartbeat tracking, and degraded-state visibility.[5] |
| **Runtime hooks** | Guard surfaces for control-plane changes, memory writes, file reads, outbound requests, message input/output, skill install, and sandbox audit.[1] |
| **Evidence store** | Records, audit chain entries, alerts, bundles, reports, and runtime metadata stored beneath the AEGX state root.[1] [5] |
| **Platform adapters** | Shell wrappers that turn the generic runtime into a concrete operator workflow for a given agent environment.[3] [6] [7] [8] |

## Why This Is Useful Inside Agent Platforms

The benefit of the hardened system is not only that it blocks bad operations. The more important benefit is that it gives each platform an explicit **operating contract**. Inside Manus, Claude Cowork / Claude Code, OpenClaw, and similar systems, safety failures often come from missing orchestration rather than missing theory. AEGX solves that by specifying when to initialize, when to heartbeat, when to verify, when to snapshot, when to stop, and what to export after an incident.[2] [5] [6] [7] [8]

| Platform problem | AEGX outcome |
|---|---|
| “I do not know whether protections are currently live.” | `aegx daemon status` and `aegx self-verify` show readiness and degraded-state conditions.[5] |
| “I need a repeatable pre-task or pre-refactor routine.” | Shipped platform adapters provide concrete modes for exactly those moments.[6] [7] [8] |
| “I need something distributable, not just source code.” | The skill bundle packages binaries, manifests, adapters, checksums, and documentation together.[4] [9] |
| “I need evidence after a problem.” | `aegx bundle export`, bundle verification, and reports preserve post-incident traceability.[5] |
| “I need to know when to halt risky work.” | Degraded-mode reporting turns partial protection into an explicit operational signal.[3] [5] [10] |

## Quick Start from Source

If you are operating from the repository rather than from a packaged bundle, use the release build and then initialize AEGX before any agent activity.[5]

```bash
cargo build --workspace --release
./target/release/aegx init
./target/release/aegx daemon start
./target/release/aegx status
./target/release/aegx self-verify --json
./target/release/aegx prove --json
```

A good minimum operator habit is to start the daemon, confirm status, run self-verification, and only then allow a risky workflow to proceed. If the daemon is unreachable or self-verification reports a degraded state, do not continue with sensitive mutations until the state is understood.[3] [5]

## Packaging the Entire System as a Usable Skill Bundle

The repository now packages the **entire usable system**, not just a manifest. The generated bundle contains the skill and agent manifests, the README, the primary CLI, the daemon binary, shared platform helpers, and the OpenClaw, Manus, and Claude Code adapter scripts. The latest validation summary confirms that the packaged bundle contains **31 artifacts**, that required paths and checksums verify cleanly, that the manifest schema is valid, that CLI help surfaces work, that `aegxd` is present, and that all three shipped adapters execute successfully as smoke tests from inside the bundle itself.[4] [9]

| Bundled entrypoint | Path in bundle | Purpose |
|---|---|---|
| Skill manifest | `SKILL.md` | Describes the packaged skill interface.[4] |
| Agent manifest | `AGENT.md` | Describes integration posture and expected usage.[2] |
| Primary CLI | `bin/aegx` | Operator-facing CLI for init, daemon control, verification, proofs, bundles, and snapshots.[5] |
| Daemon binary | `bin/aegxd` | Background daemon for authenticated IPC and runtime status.[5] |
| OpenClaw adapter | `integrations/openclaw/openclaw_adapter.sh` | OpenClaw-specific lifecycle wrapper.[6] |
| Manus adapter | `integrations/manus/manus_adapter.sh` | Manus-specific lifecycle wrapper.[7] |
| Claude adapter | `integrations/claude-code/claude_code_adapter.sh` | Claude Cowork / Claude Code lifecycle wrapper.[8] |

To create and validate a distributable bundle from the repository, use the packaging scripts directly.

```bash
bash packaging/skill/package_skill.sh --bundle-version v1
bash packaging/skill/validate_skill_bundle.sh --bundle dist/provenable-skill-v1
```

To use the packaged result after it has been built, unpack the tarball if necessary and run from the staged bundle directory.

```bash
tar -xzf dist/provenable-skill-v1.tar.gz -C /tmp
cd /tmp/provenable-skill-v1
./bin/aegx init
./bin/aegx daemon start
./bin/aegx self-verify --json
```

The adapters were hardened so that bundled execution is usable by default. They prefer bundled binaries when present, fall back to a source-tree release build only when necessary, choose a shorter HOME-based default state path to avoid Unix-socket length failures, and preserve degraded-state logs instead of aborting simply because a check returns a non-ideal status.[3] [4] [9]

## Core CLI Surfaces You Will Use Most Often

The hardened workflow is centered on a small set of commands. In practice, these are the commands that matter for daily operation.[5]

| Command | Purpose |
|---|---|
| `aegx init` | Create the AEGX state directory, policy directory, runtime directory, and workspace.[5] |
| `aegx status` | Show state initialization, record counts, snapshot counts, and daemon visibility.[5] |
| `aegx daemon start` | Launch the background daemon and wait for responsive IPC.[5] |
| `aegx daemon status` | Show live daemon reachability and degraded reasons.[5] |
| `aegx daemon heartbeat --agent-id <id> --session-id <id>` | Mark an agent session as still live.[3] |
| `aegx self-verify --json` | Run passive self-verification against current runtime state.[5] |
| `aegx self-verify --active --json` | Execute active deny probes and runtime readiness checks before risky work.[5] |
| `aegx prove --json` | Summarize current protection and health posture.[5] |
| `aegx snapshot create <name> --scope full` | Preserve a rollback point before risky changes.[3] [6] [7] [8] |
| `aegx bundle export` | Export evidence after an incident or investigation checkpoint.[5] |

## Step-by-Step Usage Inside Manus

The Manus adapter formalizes the workflow around task start, destructive actions, turn boundaries, and incidents. It is built for the case where a task may last long enough that runtime health and heartbeats need to stay observable instead of being assumed.[7]

### Manus workflow

Begin a task by bootstrapping AEGX, ensuring the daemon is running, sending a heartbeat, and collecting the initial status and self-verification evidence.

```bash
MANUS_MODE=before-task \
  bash integrations/manus/manus_adapter.sh <session-id>
```

Before a destructive action, create a snapshot, emit another heartbeat, and run active self-verification.

```bash
MANUS_MODE=before-destructive-action \
  bash integrations/manus/manus_adapter.sh <session-id>
```

After a turn, refresh liveness and query current protection posture.

```bash
MANUS_MODE=after-turn \
  bash integrations/manus/manus_adapter.sh <session-id>
```

After an incident, export the evidence bundle and review degraded-mode guidance.

```bash
MANUS_MODE=after-incident \
  bash integrations/manus/manus_adapter.sh <session-id>
```

The Manus contract is explicit: run `aegx prove --json` before risky work, keep `aegxd` alive for the full task, and route persistent memory writes or sensitive reads through guarded hook surfaces whenever the host wrapper exists.[7]

| Manus moment | What the adapter does | Operator outcome |
|---|---|---|
| **Before task** | Bootstrap, heartbeat, guard preflight. | You start with visible state instead of assumptions.[7] |
| **Before destructive action** | Snapshot, heartbeat, active self-verification. | You get a rollback point plus a live readiness check.[7] |
| **After turn** | Heartbeat plus `prove --json`. | You can monitor protection drift during longer tasks.[7] |
| **After incident** | Evidence export plus degraded-mode guidance. | You retain post-incident traceability.[7] |

## Step-by-Step Usage Inside Claude Cowork / Claude Code

The Claude adapter is tuned for coding sessions, refactors, and bursts of tool use. It treats degraded daemon state as a hard stop for risky repository mutations and makes proof plus self-verification part of the expected rhythm before large edits.[8]

### Claude Cowork / Claude Code workflow

Start the coding session with full bootstrap, heartbeat emission, and guard preflight.

```bash
CLAUDE_MODE=before-session \
  bash integrations/claude-code/claude_code_adapter.sh <session-id>
```

Before a refactor or major mutation, create a snapshot, emit a heartbeat, and run active self-verification.

```bash
CLAUDE_MODE=before-refactor \
  bash integrations/claude-code/claude_code_adapter.sh <session-id>
```

After a burst of tool calls, ask the daemon for live status.

```bash
CLAUDE_MODE=after-tool-burst \
  bash integrations/claude-code/claude_code_adapter.sh <session-id>
```

After an incident, export the bundle and retain the degraded-mode statement with the evidence.

```bash
CLAUDE_MODE=after-incident \
  bash integrations/claude-code/claude_code_adapter.sh <session-id>
```

The Claude session-start contract says to keep `aegxd` running throughout the coding session, treat degraded daemon state as a hard stop for risky repository mutations, and use both `aegx prove --json` and `aegx self-verify --json` before major edits or tool-driven refactors.[8]

| Claude moment | What the adapter does | Operator outcome |
|---|---|---|
| **Before session** | Bootstrap, heartbeat, preflight. | Session starts with visible guard posture.[8] |
| **Before refactor** | Snapshot plus active checks. | Refactors gain rollback plus live verification.[8] |
| **After tool burst** | Query daemon status. | You can confirm the daemon remained healthy during intensive tool use.[8] |
| **After incident** | Export evidence. | You preserve a forensic trail for later review.[8] |

## Step-by-Step Usage Inside OpenClaw and Related Variants

The OpenClaw adapter is especially useful where skill installation and agent-turn boundaries need explicit control. It provides a concrete skill-install gate rather than leaving that policy step implicit.[6]

### OpenClaw workflow

Run preflight before the session or environment becomes busy.

```bash
OPENCLAW_MODE=preflight \
  bash integrations/openclaw/openclaw_adapter.sh <session-id>
```

Before skill installation, create a rollback snapshot and enforce the skill-install gate.

```bash
OPENCLAW_MODE=before-skill-install \
  bash integrations/openclaw/openclaw_adapter.sh <session-id>
```

Before an agent turn, re-bootstrap if needed, emit a heartbeat, and run the standard preflight status flow.

```bash
OPENCLAW_MODE=before-agent-turn \
  bash integrations/openclaw/openclaw_adapter.sh <session-id>
```

After an incident, export the evidence bundle.

```bash
OPENCLAW_MODE=after-incident \
  bash integrations/openclaw/openclaw_adapter.sh <session-id>
```

The OpenClaw skill-install contract has three steps: route skill verification through the AEGX skill-install hook path, refuse installation if self-verification or daemon status is degraded, and keep the generated snapshot so rollback remains available if later evidence shows compromise.[6]

| OpenClaw moment | What the adapter does | Operator outcome |
|---|---|---|
| **Preflight** | Bootstrap, heartbeat, active preflight, degraded contract. | You know whether the environment is safe enough to proceed.[6] |
| **Before skill install** | Snapshot plus install gate. | Skill onboarding becomes reversible and policy-aware.[6] |
| **Before agent turn** | Heartbeat plus preflight status. | Turn execution stays observable rather than blind.[6] |
| **After incident** | Export bundle. | Investigation artifacts are preserved.[6] |

## Using the Same Pattern in Related Variants

The three shipped adapters are concrete examples, but the operating pattern generalizes cleanly to other agent harnesses and OpenClaw-like variants. The transferable sequence is to bootstrap once, keep the daemon alive, emit heartbeats at meaningful lifecycle edges, run passive or active self-verification before risky steps, snapshot before destructive changes, and export evidence after incidents.[3] [5] [6] [7] [8]

| Lifecycle edge | Recommended action |
|---|---|
| **Session start** | `aegx init`, `aegx daemon start`, `aegx self-verify --json` |
| **Before risky action** | `aegx snapshot create ...`, `aegx self-verify --active --json` |
| **During long task** | `aegx daemon heartbeat --agent-id ... --session-id ...`, then `aegx prove --json` |
| **After suspicious event** | `aegx daemon status`, `aegx bundle export` |
| **When degraded mode appears** | Stop risky work, inspect logs, choose safer workflow, or escalate.[3] |

## Outcomes and Benefits of the Final Hardened Packaging

The repository is now stronger in a way that is operationally meaningful. First, the packaged bundle is usable as a full system rather than as documentation plus binaries only. Second, the adapters are validated from inside the bundle itself. Third, the adapters choose state paths that avoid common Unix-socket path failures in deep bundle directories. Fourth, degraded-mode states are logged and surfaced rather than silently discarding the workflow. These changes make the system more portable, more truthful about its health, and easier to apply inside real agent loops.[3] [4] [9] [10]

| Improvement | Concrete effect |
|---|---|
| **Bundled binary preference** | Packaged adapters run directly from the shipped bundle without assuming a source checkout.[3] |
| **Shorter default runtime path** | Packaged execution avoids Unix socket path-length failures in deep directories.[3] |
| **Smoke-tested platform wrappers** | OpenClaw, Manus, and Claude adapter workflows were validated from the packaged bundle itself.[9] |
| **Degraded-state preservation** | Non-ideal verification states are logged and surfaced instead of causing opaque adapter failure.[3] [10] |
| **Portable operator contract** | Teams can reproduce the same lifecycle across multiple agent environments.[2] [6] [7] [8] |

## Validation Results and Current Caveats

The final repository includes evidence for both packaging success and runtime behavior. The most recent bundle validation reports `overall_ok: true`, validates checksums and manifest schema, confirms the two CLIs are usable, verifies `aegxd` is present, and passes smoke tests for the OpenClaw, Manus, and Claude adapters from the packaged bundle.[9] The broader Phase 5 validation matrix also shows that active self-verification successfully exercised deny probes for control-plane, memory-write, message-input, file-read, network-egress, and sandbox-audit checks.[10]

At the same time, the validation evidence should be read honestly. The Phase 5 runtime log recorded a **Partial** sandbox-compliance result in the current environment, which means degraded-mode reporting is functioning and should not be ignored.[10] That same matrix also captured one failing runtime test, `rollback_policy::tests::test_denial_tracker_prune`, so the repository should be described as **hardened and operationally usable**, while also acknowledging that one empirical validation item remained open in that specific matrix.[10]

| Validation area | Observed result |
|---|---|
| **Packaged bundle validation** | Passed with `overall_ok: true` and all adapter smoke tests passing.[9] |
| **Active self-verification** | Deny probes succeeded across multiple guard surfaces.[10] |
| **Daemon readiness** | Reachable over authenticated IPC once started.[10] |
| **Sandbox audit** | Reported `Partial` compliance in the validation environment, correctly surfacing degraded mode.[10] |
| **Full workspace matrix** | One runtime test failure was recorded in the captured matrix: `test_denial_tracker_prune`.[10] |

## Recommended Operator Checklist

For real use, treat AEGX as a control loop rather than a one-time installer. Start every session by verifying runtime readiness, and end every incident by exporting evidence.[3] [5]

1. Build or unpack the system.
2. Initialize AEGX state.
3. Start the daemon and confirm status.
4. Run passive or active self-verification, depending on risk.
5. Use the platform adapter mode that matches the lifecycle moment.
6. Snapshot before destructive or hard-to-reverse changes.
7. Emit heartbeats during long-running work.
8. If degraded mode appears, stop risky operations and investigate.
9. Export a bundle after incidents or review checkpoints.

## Repository Layout

| Path | Purpose |
|---|---|
| `crates/aegx-cli` | CLI entrypoints for operators and scripts.[5] |
| `crates/aegx-daemon` | Always-on daemon and authenticated IPC.[5] |
| `crates/aegx-runtime` | Runtime hooks, self-verification, proof surfaces, rollback logic.[1] [5] |
| `crates/aegx-guard` | Policy and security guard implementations.[1] |
| `crates/aegx-records` | State-path configuration, records, alerts, audit chain.[1] |
| `integrations/common` | Shared helper used by all platform adapters.[3] |
| `integrations/openclaw` | OpenClaw adapter workflow.[6] |
| `integrations/manus` | Manus adapter workflow.[7] |
| `integrations/claude-code` | Claude Cowork / Claude Code adapter workflow.[8] |
| `packaging/skill` | Bundle creation and validation scripts.[4] [9] |
| `results` | Validation summaries and empirical output logs.[9] [10] |

## Additional Documentation

| Guide | Purpose |
|---|---|
| [Installation Guide](docs/INSTALL.md) | Build and install instructions. |
| [Quickstart Tutorial](docs/QUICKSTART.md) | Baseline CLI walkthrough. |
| [CLI Reference](docs/CLI_REFERENCE.md) | Detailed command reference. |
| [Agent Integration Guide](docs/AGENT_INTEGRATION.md) | Longer-form operational integration guidance. |
| [Verification Guide](docs/VERIFICATION_GUIDE.md) | How verification outputs should be interpreted. |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Common runtime and packaging issues. |

## License

Copyright 2026 Daniel Foo Jun Wei / Provenable.ai.

The source code in this repository is licensed under the MIT License. See [LICENSE](LICENSE) for the full terms.

## References

[1]: ./docs/HARDENING_BASELINE_AUDIT.md "Hardening Baseline Audit"
[2]: ./AGENT.md "AGENT.md"
[3]: ./integrations/common/aegx_platform_common.sh "Shared Platform Adapter Helper"
[4]: ./packaging/skill/package_skill.sh "Skill Bundle Packaging Script"
[5]: ./docs/AGENT_INTEGRATION.md "Agent Integration Guide"
[6]: ./integrations/openclaw/openclaw_adapter.sh "OpenClaw Adapter"
[7]: ./integrations/manus/manus_adapter.sh "Manus Adapter"
[8]: ./integrations/claude-code/claude_code_adapter.sh "Claude Code Adapter"
[9]: ./results/skill_bundle_validation_latest.json "Latest Skill Bundle Validation Summary"
[10]: ./results/phase5_validation_matrix.log "Phase 5 Validation Matrix"
