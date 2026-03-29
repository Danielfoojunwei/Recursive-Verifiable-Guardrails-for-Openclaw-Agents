---
name: package-plugin
description: >
  Package a grounded agent bundle as a plugin for a target harness. Use when the user asks to
  "package this as a plugin", "create a plugin from the bundle", "generate plugin artifacts",
  "make this work with Claude", "make this work with Manus", "run agent-see plugin",
  or wants to turn their converted bundle into a distributable plugin.
---

# Package Agent Bundle as Plugin

Run the Agent-See plugin packaging layer to wrap a grounded agent bundle for a specific target harness.

## Pre-flight

1. Verify `agent-see` is installed (install if missing — see convert-source skill).
2. Confirm a grounded agent bundle exists. Check for `agent_card.json`:
   ```bash
   ls <output-dir>/agent_card.json
   ```
3. If no bundle exists, inform the user they need to run conversion first.

## Target Harness Selection

Default to **Claude workspace** format. If the user wants a different target, support these options:

| Harness | Description | Recommended artifact mix |
|---------|-------------|------------------------|
| **Claude** | Claude workspaces / Cowork plugins | MCP runtime or OpenAPI, AGENTS guidance, plugin guide |
| **Manus** | Manus-style agents | MCP runtime, AGENTS guidance, skills, readiness outputs |
| **OpenClaw** | OpenClaw-like orchestrators | Runtime metadata, agent card, route map, connector guide |
| **Generic** | Any other agent system | OpenAPI, AGENTS guidance, plugin manifest, starter kit |

## Run Plugin Packaging

Basic packaging (defaults to Claude format):

```bash
agent-see plugin sync <output-dir>
```

With explicit launch output directory:

```bash
agent-see plugin sync <output-dir> --launch-output ./launch-output
```

## Post-Packaging Review

Read and summarize the generated plugin artifacts:

1. **`plugins/plugin_manifest.json`** — machine-readable inventory of the grounded bundle
2. **`plugins/PLUGIN_GUIDE.md`** — step-by-step usage instructions for the target harness
3. **`plugins/connectors/`** — harness-specific connection guides
4. **`plugins/starter_kit/`** — templates for customization:
   - `plugin_template.md` — packaging template
   - `skill_template.md` — skill creation template
   - `connector_template.md` — connector creation template

## Claude Workspace Specifics

When packaging for Claude, verify the output includes:

- A valid plugin manifest compatible with `.claude-plugin/plugin.json` format
- Skills formatted as `skills/*/SKILL.md` with proper YAML frontmatter
- MCP server configuration if the bundle includes a runtime endpoint
- README with setup and usage instructions

## Providing Connection Instructions

After packaging, give the user clear next steps for their chosen harness:

### Claude / Cowork
1. Copy the generated plugin directory to the Cowork plugins folder
2. Or zip it as a `.plugin` file for distribution
3. Configure any required environment variables for MCP connections

### Manus
1. Register the MCP server endpoint with the Manus agent runtime
2. Load the skills and AGENTS guidance into the agent context
3. Configure authentication tokens

### OpenClaw
1. Register the agent card with the OpenClaw orchestrator registry
2. Configure the route map for request routing
3. Set up the connector for the runtime protocol

### Generic
1. Use the OpenAPI spec for direct API integration
2. Load the AGENTS.md guidance into the agent's system prompt
3. Adapt the starter kit templates for the specific runtime

For detailed harness-specific guidance, see `references/harness-guides.md`.
