---
name: launch-artifacts
description: >
  Generate public discovery and trust artifacts for an agent bundle. Use when the user asks to
  "generate launch artifacts", "create the public layer", "make this discoverable",
  "generate llms.txt", "create the agents page", "run agent-see launch",
  or wants to publish their converted bundle publicly.
---

# Generate Launch Artifacts

Run the Agent-See launch layer to produce public-facing discovery, trust, and maintenance artifacts from an existing grounded agent bundle.

## Pre-flight

1. Verify `agent-see` is installed (install if missing — see convert-source skill).
2. Confirm a grounded agent bundle exists at the expected output path. Check for `agent_card.json` as the sentinel file:
   ```bash
   ls <output-dir>/agent_card.json
   ```
3. If no bundle exists, inform the user they need to run conversion first.

## Launch Intake

Check if a launch intake file exists:

```bash
ls <output-dir>/../launch-intake.json 2>/dev/null || ls ./launch-intake.json 2>/dev/null
```

If no intake file exists, generate one from the template:

```bash
agent-see launch init --bundle <output-dir> --output ./launch-intake.json
```

Review the generated intake file with the user. Key fields to confirm:

- **Business name and URL** — must match the source
- **Public page locations** — where `llms.txt` and `/agents` page will live
- **Trust signals** — any certifications, compliance, or guarantees to surface
- **Contact information** — operator contact for agent-related issues

## Generate Launch Layer

Run the launch sync command:

```bash
agent-see launch sync ./launch-intake.json --bundle <output-dir> --output ./launch-output
```

## Post-Generation Review

Read and summarize the launch outputs:

1. **`launch/llms.txt`** — model-facing discovery guide. Verify it accurately describes the public pages.
2. **`launch/agents.md`** — public instructions page for agent access. Check for truthfulness.
3. **`launch/reference_layer/`** — supporting usage, limitation, trust, and policy pages.
4. **`launch/launch_report.md`** — readiness report. Flag any warnings.
5. **`launch/surface_alignment.json`** — check that public claims match actual runtime capabilities.
6. **`launch/update_register.md`** — maintenance plan for future refreshes.

## Truthfulness Check

Run the alignment check:

```bash
agent-see launch check ./launch-output --bundle <output-dir>
```

If misalignments are found, report them and ask the user whether to regenerate or manually fix.

## Publication Guidance

After launch artifacts pass review, explain the publish vs deploy distinction:

| Asset | Where it goes | Action required |
|-------|--------------|-----------------|
| `llms.txt` | Public website root | User must upload/deploy |
| `/agents` page | Public website or docs | User must publish |
| Reference pages | Public docs | User must publish |
| Runtime service | Server infrastructure | User must deploy |
| Reports & registers | Internal docs | No public action needed |

For detailed artifact descriptions, see `references/launch-artifacts-detail.md`.
