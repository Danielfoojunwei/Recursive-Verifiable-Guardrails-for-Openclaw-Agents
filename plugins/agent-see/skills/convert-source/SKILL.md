---
name: convert-source
description: >
  Convert a business surface into a grounded agent bundle. Use when the user asks to
  "convert a website", "turn this SaaS into a plugin", "create an agent bundle",
  "extract capabilities from this URL", "convert this API", "run agent-see convert",
  or provides a URL or OpenAPI spec file to process.
---

# Convert Source to Agent Bundle

Run the Agent-See conversion pipeline to transform a website URL, SaaS product URL, or OpenAPI specification file into a grounded agent bundle.

## Pre-flight

1. Check if `agent-see` is installed:
   ```bash
   agent-see --version 2>/dev/null
   ```
2. If not installed, auto-install from the repository:
   ```bash
   pip install git+https://github.com/Danielfoojunwei/Convert-any-SaaS-application-into-an-Agentic-interface.git --break-system-packages
   ```
3. Verify installation succeeded before continuing.

## Determine Source Type

Identify the source from the user's input:

| User provides | Source type | Example |
|---------------|------------|---------|
| A website URL | Website | `https://example.com` |
| A SaaS product URL | SaaS | `https://app.example.com` |
| A local file path ending in `.json`, `.yaml`, or `.yml` | OpenAPI spec | `./openapi.json` |

If the source type is ambiguous, ask the user to clarify.

## Run Conversion

Set the output directory. Default to `./agent-output` unless the user specifies otherwise.

```bash
agent-see convert <source> --output <output-dir>
```

For verbose output (recommended for first-time conversions):

```bash
agent-see convert <source> --output <output-dir> --verbose
```

## Post-Conversion Review

After conversion completes, read and summarize the key outputs:

1. **Read `agent_card.json`** — confirm identity and discovery metadata
2. **Read `AGENTS.md`** — verify the agent/operator guidance is accurate
3. **Read `openapi.yaml`** — check the API contract was captured correctly
4. **List `skills/`** — enumerate the business action wrappers generated
5. **Read `OPERATIONAL_READINESS.md`** — review execution boundaries

Present a structured summary to the user:

- Number of skills/actions extracted
- Key workflows captured
- Any warnings about login, approval, or state-change boundaries
- Whether the bundle looks complete or needs re-running with adjusted scope

## Handling Failures

If conversion fails:

1. Read the error output carefully
2. Common issues:
   - **Network errors**: Check URL accessibility
   - **Missing Playwright**: Run `playwright install chromium`
   - **OpenAPI parse errors**: Validate the spec file format
3. Report the specific error and suggest remediation

## Reference Material

For detailed output artifact descriptions, see `references/output-artifacts.md`.
