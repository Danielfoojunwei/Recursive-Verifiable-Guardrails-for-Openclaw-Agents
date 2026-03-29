# Conversion Output Artifacts

Complete reference for every artifact produced by `agent-see convert`.

## Core Bundle Files

### `mcp_server/`
The callable tool surface for agents. Contains `server.py` (the MCP server implementation), deployment configs (Dockerfile, docker-compose.yml, fly.toml, railway.json, render.yaml), and runtime metadata (route_map.json, tool_metadata.json, runtime_state.json).

### `openapi.yaml`
Machine-readable API contract generated from the source surface. Includes all discovered endpoints, request/response schemas, authentication requirements, and rate limits.

### `agent_card.json`
Identity and discovery metadata following the agent card specification. Contains the agent name, description, capabilities, supported protocols, and trust signals.

### `AGENTS.md`
Human and agent-readable guidance document. Describes what the integration does, how to use it, operational boundaries, and caveats. This is the primary document agents read to understand the integration.

### `OPERATIONAL_READINESS.md`
Practical execution boundaries summary. Documents what actions require authentication, which operations are state-changing, rate limits, and known limitations.

## Skills Directory

### `skills/*.md`
Each skill file wraps a single business action extracted from the source surface. Examples: `list_products.md`, `add_to_cart.md`, `submit_checkout.md`, `get_order_status.md`.

### `skills/workflows/*.md`
Composite workflow files that chain multiple skills into end-to-end business processes. Example: `purchase_flow.md` chains product search, cart management, and checkout.

## Proof Directory

### `proof/`
Grounding evidence that validates the extraction stayed truthful. Contains screenshots, DOM snapshots, API response samples, and cross-validation reports.

## Capability Graph

### `capability_graph.json`
Structured graph of all discovered capabilities and their relationships. Nodes represent actions, edges represent dependencies and sequencing constraints.
