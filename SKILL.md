---
name: provenable
description: Provable security guardrails for agentic AI. Audit agent actions, check protection status, query threat alerts, manage snapshots, verify evidence bundles, and enforce CPI/MI guard policies with the unified aegx CLI.
user-invocable: true
metadata:
  openclaw:
    emoji: shield
    os:
      - linux
      - darwin
    requires:
      bins:
        - aegx
    install:
      - url: https://github.com/Danielfoojunwei/Provenable-Recursive-Verifiable-Guardrails-for-Agentic-AI.git
        targetDir: ~/.proven
---

# Provenable.ai — Provable Security Guardrails for Agentic AI

> **This file is the skill definition.** Import this repo as a skill in
> [OpenClaw](https://openclaw.ai), [Claude Code](https://claude.ai),
> [Manus](https://manus.im), or any agent platform that reads `SKILL.md`.
> See also: [`AGENT.md`](AGENT.md) for agent-level integration instructions.

Single CLI: `aegx` — unified evidence format, runtime guards, snapshots,
rollback, bundle verification, and `/prove` query interface.

## Mandatory Intake Behavior for Conversion Work

When this repository is loaded as a skill, the agent must treat any
**conversion, transformation, migration, rewrite, adaptation, packaging,
reformatting, or platform-porting request** as an intake-first workflow.
The agent must **ask clarifying questions early, collect every critical input,
and avoid beginning the conversion itself until the required information is
complete**.

A shallow request such as "convert this," "make this into X," "port this to
Y," or "turn this into a skill/agent/app/workflow" is **not** sufficient to
start high-quality work. The agent must pause and gather the missing context.

### Required Pre-Conversion Checklist

Before starting conversion work, the agent must confirm or request all
applicable information below and treat the checklist as a **required gate**.
If any critical item is missing, the agent must stop and ask for it.

| Checklist item | What the agent must obtain from the user | Required to proceed |
|---|---|---|
| **Source material** | The exact files, URLs, repositories, prompts, notes, screenshots, examples, or assets that will be converted | **Yes** |
| **Target outcome** | The destination format, platform, runtime, schema, framework, or output form the user wants | **Yes** |
| **Quality bar** | What “highest level” means for this task: production-ready, visually polished, enterprise-safe, launch-ready, academically rigorous, and so on | **Yes** |
| **Audience and use case** | Who will use the converted result, in what setting, and for what job to be done | **Yes** |
| **Preserve vs. change** | What must remain unchanged, what may be improved, and what should be removed or replaced | **Yes** |
| **Style and voice** | Brand voice, tone, structure, terminology, naming, and formatting preferences | If relevant |
| **Technical constraints** | Required languages, frameworks, APIs, deployment targets, integration points, security rules, and environment constraints | **Yes** for technical conversions |
| **Examples and benchmarks** | Reference outputs, competitor examples, prior versions, or design inspiration that define success | If available, otherwise explicitly note absence |
| **Acceptance criteria** | How the user will judge success, including test cases, review criteria, deliverables, and definition of done | **Yes** |
| **Operational constraints** | Timeline, priority, dependencies, ownership, compliance requirements, and anything the agent must not do | **Yes** |

### Explicit Stop Conditions

The agent must **pause and ask questions instead of converting** if any of the
following is true.

1. The source material is missing, incomplete, or ambiguous.
2. The target output is not precisely defined.
3. The user has not defined what quality level or success looks like.
4. The constraints, dependencies, or integrations are unclear.
5. The deliverables or acceptance criteria are missing.
6. The request uses vague phrases such as “convert this,” “make it better,” or
   “do it at the highest level” without enough operational detail.
7. The agent would otherwise need to invent assumptions that could materially
   change the outcome.

### Mandatory Agent Intake Rules

1. The agent must **ask for missing information in a structured batch** rather
   than making weak assumptions.
2. The agent must **not start the actual conversion** until the required
   checklist items are present, unless the user explicitly authorizes
   assumptions.
3. If assumptions are allowed, the agent must **state them clearly, list them,
   and ask for confirmation** before proceeding.
4. If files, repositories, credentials, examples, environment details, or
   approval criteria are missing, the agent must **request them directly**.
5. If the request is underspecified, the agent must optimize for
   **completeness and correctness**, not speed.
6. The agent should prefer one high-quality discovery round that gathers the
   full brief over many fragmented follow-ups.
7. If the user asks for “best possible” or “highest level” conversion, the
   agent must actively seek hidden requirements instead of relying only on the
   initial wording.
8. The agent must treat the intake checklist as a **hard precondition**, not a
   suggestion.

### Required Discovery Questions for Any Major Conversion

The agent should ask a grouped intake message covering at least the following:

- What exactly should be converted?
- What is the target format, platform, or end state?
- Who is the final audience or operator?
- What should stay the same, and what should change?
- What good reference examples should this match or beat?
- What constraints, integrations, or compatibility requirements apply?
- What output files or deliverables do you expect?
- How will you evaluate whether the conversion is successful?
- What assumptions, if any, do you want the agent to avoid making?

Only after that checklist is complete should the agent move into planning,
implementation, validation, and delivery.

## Setup (one-time)

Build from source:

```bash
cd {baseDir}
cargo build --workspace --release
export PATH="{baseDir}/target/release:$PATH"
```

Initialize the guardrail runtime:

```bash
aegx init
```

Creates the state directory, installs the default policy, and sets up the
workspace. Outputs a policy summary showing the default rules.

## Quick Status — "How am I protected?"

```bash
aegx prove --json
```

Returns protection summary, threat alerts, guard metrics, and system health as JSON.

Human-readable output (no `--json`):

```bash
aegx prove
```

## Query Alerts

Show recent alerts:

```bash
aegx prove --limit 10
```

Filter by severity:

```bash
aegx prove --severity CRITICAL
```

Filter by threat category and time range:

```bash
aegx prove --category CPI --since 2026-02-01T00:00:00Z
```

## Check System Health

```bash
aegx status
```

Shows: initialized state, record count, audit chain integrity, snapshot count.

## Snapshots and Rollback

Create a snapshot before risky operations:

```bash
aegx snapshot create "pre-deploy" --scope full
```

List snapshots:

```bash
aegx snapshot list
```

Rollback to a snapshot:

```bash
aegx rollback <SNAPSHOT_ID>
```

## Evidence Bundles

Export an evidence bundle for audit:

```bash
aegx bundle export --agent <AGENT_ID>
```

Verify a bundle:

```bash
aegx verify <BUNDLE_PATH>
```

Generate a report from a bundle:

```bash
aegx report <BUNDLE_PATH>
```

## Guard Behavior

When the guard denies an action:

1. The denial is automatically recorded as a `GuardDecision` record
2. A `ThreatAlert` is emitted with severity and category
3. Do NOT retry the same action — the policy will deny it again
4. Escalate to the user or choose an alternative path

## Guard Surfaces (v0.2.0)

### Control-Plane Integrity (CPI)

Blocks untrusted principals from modifying skills, tools, permissions, and
gateway configuration. Only `USER` and `SYS` principals can alter the control
plane. Cross-surface integration: CPI denial escalates MI taint for that
principal.

### Memory Integrity (MI)

Blocks untrusted writes to durable memory files (`SOUL.md`, `AGENTS.md`,
`TOOLS.md`, `USER.md`, `IDENTITY.md`, `HEARTBEAT.md`, `MEMORY.md`). All
writes route through the hooks pipeline for full audit trail.

### Conversation I/O (Noninterference)

8-category prompt injection scanner analyzes inbound messages. Output leakage
detector scans outbound responses for system prompt tokens. Injection detected
in a session taints all subsequent operations session-wide.

### File Read Guard

Blocks untrusted principals from reading sensitive files:
- Denied: `.env*`, `*.pem`, `*.key`, `id_rsa*`, `id_ed25519*`, `credentials`
- Tainted: `.aws/*`, `.ssh/*`, `.gnupg/*` propagate `SECRET_RISK`

### Network Egress Monitor

Evaluates outbound requests against domain blocklist/allowlist:
- Blocked by default: `webhook.site`, `requestbin.com`, `pipedream.net`, `canarytokens.com`, `interact.sh`

### Sandbox Audit

Verifies OS execution environment at session start:
- Container detection (Docker, Kubernetes)
- Seccomp filter status, namespace isolation
- Emits CRITICAL alert if no sandboxing detected

### Cross-Surface Threat Correlation (v0.2.0)

- CPI denial → MI taint escalation for that principal
- Injection detection → session-wide taint across all surfaces
- Cross-surface denial count → RVU auto-rollback threshold

## Common Chat Queries Mapped to Commands

| User says | Run |
|-----------|-----|
| "Am I protected?" | `aegx prove --json` |
| "Any threats?" | `aegx prove --severity MEDIUM --limit 20` |
| "Show critical alerts" | `aegx prove --severity CRITICAL` |
| "What did the guard block?" | `aegx prove --category CPI` |
| "System health" | `aegx status` |
| "Take a snapshot" | `aegx snapshot create "user-requested"` |
| "List snapshots" | `aegx snapshot list` |
| "Roll back" | `aegx snapshot list` then `aegx rollback <ID>` |
| "Export evidence" | `aegx bundle export` |
| "Verify this bundle" | `aegx verify <PATH>` |
| "Guard performance" | `aegx prove --json` (check `.metrics`) |
| "Is my environment sandboxed?" | `aegx prove --json` (check sandbox in health) |

## CLI Reference

| Command | Description |
|---------|-------------|
| `aegx init` | Initialize state dirs, default policy, workspace |
| `aegx status` | Show initialization status, counts, chain validity |
| `aegx snapshot create <name> [--scope full\|cp\|mem]` | Create a named snapshot |
| `aegx snapshot list` | List existing snapshots |
| `aegx rollback <snapshot-id>` | Rollback to a previous snapshot |
| `aegx bundle export [--agent <id>] [--since <ts>]` | Export evidence bundle |
| `aegx verify <path>` | Verify bundle integrity (10-step) |
| `aegx report <path>` | Generate report from bundle |
| `aegx prove [--json] [--category <cat>] [--severity <sev>] [--since <ts>]` | Query protection status |

## Safety Rules

1. Never bypass guard denials — they exist to protect the system
2. Always create a snapshot before destructive operations
3. Always verify bundles before trusting them (`aegx verify`)
4. Guard denials should be escalated to the user, never silently retried
5. Rollback restores file content only — it cannot reverse external API calls
