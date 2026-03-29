# Agent-See Plugin

Convert any website, SaaS product, or API into a plugin-ready agentic interface.

## What This Plugin Does

Agent-See transforms real business surfaces into grounded agent bundles — structured packages that agents can discover, trust, and execute against. Rather than rewriting existing services, it creates a verified wrapper layer that exposes business capabilities safely to AI agents.

## Skills

### Convert Source
Turn a website URL, SaaS product URL, or OpenAPI specification into a grounded agent bundle. The conversion extracts business actions, generates an MCP server, and creates operational documentation.

**Trigger phrases**: "convert a website", "turn this SaaS into a plugin", "create an agent bundle", "convert this API"

### Launch Artifacts
Generate the public discovery and trust layer for a converted bundle. Produces `llms.txt`, an agents page, reference documentation, and alignment checks.

**Trigger phrases**: "generate launch artifacts", "create the public layer", "make this discoverable"

### Package Plugin
Wrap a grounded agent bundle as a distributable plugin for a target harness. Supports Claude workspaces (default), Manus agents, OpenClaw orchestrators, and generic systems.

**Trigger phrases**: "package this as a plugin", "make this work with Claude", "generate plugin artifacts"

### Verify Bundle
Assess conversion quality across coverage, fidelity, and hallucination metrics. Identifies gaps and recommends remediation.

**Trigger phrases**: "verify the bundle", "check conversion quality", "audit the conversion"

## Setup

### Requirements

- Python 3.11+
- The `agent-see` CLI tool

### Installation

The plugin auto-installs `agent-see` when first triggered if it is not already available. Manual installation:

```bash
pip install git+https://github.com/Danielfoojunwei/Convert-any-SaaS-application-into-an-Agentic-interface.git
```

### Browser Automation (Optional)

For website and SaaS URL conversion, Playwright is required:

```bash
playwright install chromium
```

## Typical Workflow

1. **Convert** — provide a URL or OpenAPI spec to create the grounded bundle
2. **Verify** — audit the conversion for quality and truthfulness
3. **Launch** — generate the public discovery and trust artifacts
4. **Package** — wrap everything as a plugin for your target harness

## Environment Variables

No environment variables are required for basic operation. Specific source surfaces may require authentication tokens set in the shell environment.
