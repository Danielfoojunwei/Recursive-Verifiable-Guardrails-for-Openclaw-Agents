# Launch Artifacts Detail

## llms.txt

A model-facing guide placed at the website root (e.g., `https://example.com/llms.txt`). It tells language models and agents which public pages are most important and how to interpret them. Format follows the emerging `llms.txt` convention.

Key sections:
- Summary of the business and what agents can do
- Links to the agents page, API docs, and key reference pages
- Authentication and access notes

## agents.md / /agents Page

The public instructions page for agent access. This is the canonical "how to use this integration" document that agents and operators read first.

Must include:
- What the integration does (grounded in conversion outputs)
- How to connect (MCP endpoint, API base URL, authentication)
- Available actions and their parameters
- Operational boundaries (rate limits, auth requirements, state-changing actions)
- Contact information for the operator

## Reference Layer

Supporting pages that provide depth beyond the main agents page:

- **Usage guide** — step-by-step instructions for common workflows
- **Limitations page** — honest documentation of what the integration cannot do
- **Trust signals** — certifications, compliance, uptime guarantees
- **Policy page** — terms of use, data handling, privacy

## Launch Report

Internal readiness assessment. Checks whether all required artifacts were generated, whether public claims are supported by the grounded bundle, and flags any gaps.

## Surface Alignment JSON

Machine-readable comparison between public claims and actual runtime capabilities. Each claim is tagged as `aligned`, `partial`, or `misaligned` with an explanation.

## Update Register

Maintenance plan documenting what to re-run when the source business changes. Includes trigger conditions, commands to execute, and expected outputs.
