# How the AEGX Guardrails System Works

> **Note:** This repository does not contain a "LoRA creator agent." It is
> **Provenable Recursive Verifiable Guardrails for Agentic AI** — a security
> enforcement system for agentic AI platforms. This document explains how the
> entire system works end-to-end.

---

## 1. Architecture Overview

The system is a **6-crate Rust workspace** with a strict layered dependency
graph (each layer depends only on layers below it):

```
aegx-cli          ← User-facing CLI (`aegx` binary)
  │
aegx-runtime      ← Hooks pipeline, snapshots, rollback policy
  │
aegx-guard        ← Policy engine, scanner, guard surfaces
  │
aegx-records      ← Record emission, audit chain, config
  │
aegx-bundle       ← Bundle export, verification, reporting
  │
aegx-types        ← Canonical JSON, hashing, type definitions
```

### What each crate does

| Crate | Purpose |
|-------|---------|
| **aegx-types** | Core types (`TypedRecord`, `GuardVerdict`, `Principal`, `TaintFlags`, `PolicyPack`), canonical JSON serialization (AEGX_CANON_0_1), SHA-256 hashing |
| **aegx-records** | Emits `TypedRecord` instances to disk as JSONL, maintains the append-only hash-linked audit chain, manages config/state directories |
| **aegx-bundle** | Exports self-contained `.aegx.zip` evidence bundles, runs 10-step verification (record hash recompute, audit chain integrity, blob hashes, manifest counts) |
| **aegx-guard** | The policy engine — loads YAML policy packs, evaluates deny/allow decisions against 3 guard surfaces, runs the 8-category prompt injection scanner, output leakage detector, file read guard, network egress monitor, skill verifier |
| **aegx-runtime** | Integration hooks (`on_tool_call`, `on_file_write`, `on_message_input`, etc.), snapshot create/list, automated rollback policy engine, sandbox audit |
| **aegx-cli** | The `aegx` binary — `init`, `status`, `prove`, `snapshot`, `rollback`, `bundle`, `verify`, `report` commands |

---

## 2. Core Concept: Tamper-Evident Evidence Chain

Every action in the system produces a **`TypedRecord`** — the fundamental
evidence unit. Each record contains:

```rust
pub struct TypedRecord {
    pub record_id: String,        // SHA-256 of canonical JSON of all fields
    pub record_type: RecordType,  // SessionStart, ToolCall, GuardDecision, etc.
    pub principal: Principal,     // Who: User, Sys, Web, Skill, Channel, etc.
    pub taint: TaintFlags,        // Bitflags: UNTRUSTED, INJECTION_SUSPECT, etc.
    pub parents: Vec<String>,     // DAG edges to parent record IDs
    pub meta: RecordMeta,         // Timestamp, agent_id, session_id, tool_id, etc.
    pub payload: Payload,         // Inline JSON or blob reference
}
```

**Record ID computation** (`aegx-types/src/canonical.rs`):
1. Build a JSON object with 7 fields: `{type, principal, taint, parents, meta, payload, schema}`
2. Canonicalize it (sorted keys, NFC-normalized strings, no whitespace, -0.0→0)
3. SHA-256 hash the canonical bytes → that's the `record_id`

Records are appended to an **audit chain** — each entry includes the hash of
the previous entry, creating a blockchain-like structure where any single bit
flip is detectable:

```rust
pub struct AuditEntry {
    pub idx: u64,
    pub ts: DateTime<Utc>,
    pub record_id: String,
    pub prev_hash: String,       // Hash of the previous entry
    pub entry_hash: String,      // Hash of this entry
}
```

---

## 3. The Guard Pipeline

The guard is the core enforcement engine (`aegx-guard/src/guard.rs`). It
implements a **fail-closed** policy: if no rule matches, the request is **denied**.

### 3.1 Three Primary Guard Surfaces

Each surface maps to a formal theorem:

| Surface | Theorem | What it protects | Entry point |
|---------|---------|-----------------|-------------|
| **ControlPlane** | CPI (Control-Plane Integrity) | Skills, tools, permissions, gateway config | `guard.check_control_plane()` |
| **DurableMemory** | MI (Memory Integrity) | `SOUL.md`, `MEMORY.md`, `IDENTITY.md`, etc. | `guard.check_memory_write()` |
| **ConversationIO** | Noninterference | Inbound messages (injection) + outbound responses (leakage) | `guard.check_conversation_input()` / `guard.check_conversation_output()` |

### 3.2 Three Extended Guard Surfaces

| Surface | What it does |
|---------|-------------|
| **FileSystem** (`file_read_guard.rs`) | Blocks untrusted principals from reading `.env*`, `*.pem`, `*.key`, SSH keys, credentials |
| **NetworkIO** (`network_guard.rs`) | Blocks outbound requests to exfiltration services (`webhook.site`, `requestbin.com`, etc.), enforces domain allowlists |
| **SandboxCompliance** (`sandbox_audit.rs`) | Verifies container detection, seccomp filters, namespace isolation at session start |

### 3.3 Policy Evaluation Flow

```
Request arrives (principal, taint, surface, approved?)
        │
        ▼
┌─────────────────────────┐
│  Load PolicyPack (YAML) │ ← SHA-256 sidecar integrity check
│  + validate safety      │ ← Rejects policies that allow untrusted CPI
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  Iterate rules in order │
│  First match wins       │
│  No match → DENY        │ ← Fail-closed
└────────────┬────────────┘
             │
     ┌───────┴───────┐
     ▼               ▼
   ALLOW           DENY
     │               │
     │               ├── Rate-limit check (100 denials/60s max)
     │               ├── Emit GuardDecision record
     │               ├── Emit ThreatAlert
     │               ├── Signal cross-surface correlation
     │               └── Feed rollback policy engine
     │
     ├── Emit GuardDecision record
     └── Emit audit chain entry
```

### 3.4 Default Policy Rules

The default policy (`aegx-guard/src/policy.rs:default_policy()`) has 8 rules:

1. **`cpi-deny-untrusted`** — Deny CPI changes from Web, Skill, Channel, External, ToolUnauth, ToolAuth
2. **`cpi-allow-authorized`** — Allow CPI changes from User, Sys
3. **`mi-deny-tainted`** — Deny memory writes with UNTRUSTED, INJECTION_SUSPECT, WEB_DERIVED, or SKILL_OUTPUT taint
4. **`mi-deny-untrusted-principal`** — Deny memory writes from Web, Skill, Channel, External
5. **`mi-allow-authorized`** — Allow memory writes from User, Sys
6. **`cio-deny-injection`** — Deny conversation with INJECTION_SUSPECT taint
7. **`cio-deny-untrusted-tainted`** — Deny tainted messages from untrusted principals
8. **`cio-allow-clean`** — Allow clean conversation messages

---

## 4. The Scanner (Prompt Injection Detection)

The 8-category prompt injection scanner (`aegx-guard/src/scanner.rs`) analyzes
inbound messages for:

| Category | What it detects |
|----------|----------------|
| **SystemImpersonation** | Fake system/admin principal claims, role hijacking |
| **IndirectInjection** | Cross-boundary taint flow from documents |
| **BehaviorManipulation** | Attempts to override behavior rules (control-plane state) |
| **FalseContextInjection** | Fabricated memory/context poisoning |
| **EncodedPayload** | Base64/hex/ROT13/Unicode-escaped attack payloads |
| **ExtractionAttempt** | System prompt extraction, instruction dumping |
| **ManyShotPriming** | Accumulated priming to override model behavior |
| **FormatOverride** | Format locks that manipulate information flow |

The scanner also includes a **Crescendo attack detector** — session-level
analysis that tracks accumulated manipulation scores across multiple messages.
If a session accumulates enough suspicious messages, it triggers a block even
if individual messages look benign.

The **output guard** (`output_guard.rs`) scans outbound LLM responses for
system prompt token leakage and structural leak patterns (markdown headers,
config blocks, etc.).

---

## 5. The Hooks Pipeline (Runtime Integration)

The hooks pipeline (`aegx-runtime/src/hooks.rs`) is how external agent
platforms integrate with AEGX. Every significant agent operation routes
through a hook function:

| Hook | What it gates | Guard surface |
|------|--------------|---------------|
| `on_session_start()` | Session creation | (record only) |
| `on_session_message()` | Message recording | (record only) |
| `on_tool_call()` | Tool invocations | (record only) |
| `on_tool_result()` | Tool results | (record only) |
| `on_control_plane_change()` | Skill installs, config changes | CPI |
| `on_file_write()` | Writes to memory files | MI |
| `on_message_input()` | Inbound user/channel messages | ConversationIO |
| `on_message_output()` | Outbound LLM responses | ConversationIO |
| `on_file_read()` | File reads | FileSystem |
| `on_outbound_request()` | Network requests | NetworkIO |
| `on_skill_install()` | Skill package verification | CPI (ClawHavoc scan) |
| `on_sandbox_audit()` | OS sandbox check | SandboxCompliance |
| `on_system_prompt_available()` | Dynamic output guard token discovery | MI (read-side) |

Each hook:
1. Evaluates the guard (if applicable)
2. Emits a `TypedRecord` regardless of verdict
3. Appends to the audit chain
4. On denial: emits alerts, signals cross-surface correlation, feeds rollback policy

---

## 6. Cross-Surface Threat Correlation

The guard surfaces are not independent — they share threat intelligence
(`aegx-guard/src/guard.rs`, lines 496–626):

```
CPI Denial for Principal P
    │
    └──▶ P's subsequent MI writes carry UNTRUSTED taint
         (attacker who tried to mutate config may also try to poison memory)

Injection Detected in Session S
    │
    └──▶ ALL subsequent operations in S carry INJECTION_SUSPECT + UNTRUSTED
         (session-wide taint propagation)

Cross-Surface Denial Count
    │
    └──▶ Feeds RVU auto-rollback threshold
         (coordinated attack across surfaces → lower threshold)
```

Correlation state expires after 5 minutes to prevent permanent false
positive taint.

---

## 7. Automated Recovery (Rollback Policy Engine)

The rollback policy engine (`aegx-runtime/src/rollback_policy.rs`)
implements the RVU (Recursive Verifiable Unlearning) theorem with three
mechanisms:

### 7.1 Auto-Snapshot Before CPI Changes

Before every allowed control-plane mutation, the system automatically
creates a snapshot (with 60-second cooldown). This ensures every
CPI change has a rollback point.

### 7.2 Rollback Recommendation (3+ denials in 2 minutes)

When 3+ guard denials occur within 120 seconds, the system emits a
`RollbackRecommended` alert with the most recent snapshot ID and a
human-readable message for the agent to relay to the user.

### 7.3 Auto-Rollback (5+ denials in 2 minutes)

When 5+ denials occur within 120 seconds (or cross-surface denial count
exceeds the threshold), the system:
1. Automatically rolls back to the most recent snapshot
2. Restores all files to their snapshot state
3. Verifies the rollback (re-hashes all restored files)
4. Emits a CRITICAL `AutoRollback` alert
5. Resets the denial tracker

### 7.4 Contamination Scope (BFS)

When output leakage is detected, the system computes the **transitive
closure** of all downstream records affected:

```
Leaking Record (source)
    │
    ├──▶ Child record A (parent = source)
    │       │
    │       └──▶ Grandchild record C (parent = A)
    │
    └──▶ Child record B (parent = source)
```

This BFS traversal identifies the full blast radius of a successful
attack — how many downstream operations were influenced by contaminated
data.

---

## 8. Bundle Export & Verification

### Export

`aegx bundle export` creates a self-contained `.aegx.zip` containing:
- `manifest.json` — bundle metadata, record/blob/audit counts, filters
- `records.jsonl` — all evidence records
- `audit-log.jsonl` — the complete audit chain
- `blobs/` — any blob-promoted payloads (>4KB)

### 10-Step Verification

`aegx verify <path>` runs:
1. Parse each record from `records.jsonl`
2. Recompute `record_id` from the 6-field canonical hash
3. Compare recomputed ID to stored ID (catches any field tampering)
4. Verify blob references exist and their SHA-256 matches
5. Parse the audit chain from `audit-log.jsonl`
6. Verify each entry's `prev_hash` matches the previous entry's `entry_hash`
7. Verify each entry's `entry_hash` matches recomputed hash of `{idx, ts, recordId, prev}`
8. Check manifest `record_count` matches actual record count
9. Check manifest `blob_count` matches actual blob count
10. Return `VerificationResult` with `valid: true/false` and any errors

Any single bit flip — in a record field, a blob, or an audit chain entry —
is caught.

---

## 9. End-to-End Flow Example

Here's what happens when an untrusted skill tries to modify `SOUL.md`:

```
1. Skill calls on_file_write(principal=Skill, file="SOUL.md", content=...)

2. Hook recognizes SOUL.md as a MEMORY_FILE → triggers MI guard

3. Guard loads policy, evaluates rules:
   - Rule "mi-deny-untrusted-principal" matches (Skill ∈ untrusted)
   → Verdict: DENY

4. Rate limit check passes (not flooding)

5. GuardDecision record emitted:
   {record_type: GuardDecision, principal: Skill, taint: empty,
    payload: {verdict: Deny, rule_id: "mi-deny-untrusted-principal", ...}}

6. Record ID computed via SHA-256(canonical_json({type, principal, taint, parents, meta, payload}))

7. Audit chain entry appended (linked to previous entry hash)

8. ThreatAlert emitted: category=MiViolation, severity=High

9. Rollback policy engine notified:
   - If this is the 3rd denial → RollbackRecommended alert
   - If this is the 5th denial → AUTO-ROLLBACK triggered

10. Hook returns Err(decision_record) → file write is blocked
```

---

## 10. CLI Reference

| Command | Description |
|---------|-------------|
| `aegx init` | Initialize state dirs, default policy, workspace |
| `aegx status` | Show initialization status, counts, chain validity |
| `aegx prove [--json]` | Query protection status, alerts, metrics |
| `aegx snapshot create <name>` | Create a named snapshot |
| `aegx snapshot list` | List existing snapshots |
| `aegx rollback <snapshot-id>` | Rollback to a previous snapshot |
| `aegx bundle export` | Export evidence bundle |
| `aegx verify <path>` | Verify bundle integrity |
| `aegx report <path>` | Generate report from bundle |
