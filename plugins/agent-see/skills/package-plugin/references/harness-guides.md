# Harness-Specific Packaging Guides

## Claude Workspaces / Cowork

Claude workspaces expect plugins in a specific directory structure:

```
plugin-name/
├── .claude-plugin/
│   └── plugin.json
├── skills/
│   └── skill-name/
│       └── SKILL.md
├── .mcp.json          (if runtime endpoint exists)
└── README.md
```

**plugin.json** must include `name`, `version`, and `description`. Skills use YAML frontmatter with `name` and `description` fields. The description must be third-person with trigger phrases in quotes.

**MCP integration**: If the converted bundle includes an MCP server, reference it in `.mcp.json`:

```json
{
  "mcpServers": {
    "agent-see-runtime": {
      "command": "python",
      "args": ["${CLAUDE_PLUGIN_ROOT}/mcp_server/server.py"],
      "env": {
        "API_BASE_URL": "${API_BASE_URL}"
      }
    }
  }
}
```

## Manus-Style Agents

Manus agents consume MCP tool surfaces directly. The key integration points:

1. **MCP endpoint URL** — the deployed server.py address
2. **Tool metadata** — from `tool_metadata.json`
3. **Skills** — loaded as operational knowledge
4. **AGENTS.md** — primary context document

Package format is typically a directory with these files plus a manifest.

## OpenClaw-Like Orchestrators

OpenClaw orchestrators route requests through agent cards and capability graphs:

1. **Agent card** — register `agent_card.json` with the orchestrator's discovery service
2. **Route map** — `route_map.json` defines request routing
3. **Capability graph** — `capability_graph.json` maps action dependencies
4. **Connector** — thin adapter bridging the orchestrator's protocol to the runtime

## Generic Harnesses

For any other agent system, provide:

1. **OpenAPI spec** — universal API contract any system can consume
2. **AGENTS.md** — human/agent-readable integration guide
3. **Plugin manifest** — structured metadata for tool registration
4. **Starter kit templates** — customizable templates for the specific runtime
