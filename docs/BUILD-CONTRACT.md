# Architecture and extension contract

Palisade's user flow is intentionally small: `/` explains the product and copies
one agent prompt; `/scan/:id` displays the live audit. The agent owns research,
verification, safe authorized remediation, and iterative re-audit. Keep new
capabilities in agent tools and the shared engine. Do not reintroduce account
onboarding, provider configuration, editors, navigation menus, or dashboards into
this flow. Results should remain legible without opening every detail.

## One engine, honest progress

`packages/core` is runtime-neutral TypeScript and owns the versioned catalog,
validation, scoring, evidence provenance, freshness and recovery graph. Clients
must not invent alternate scores. A nullable posture score and separate coverage
are evaluated from the same state, versions and timestamp. All inventoried assets
count; importance changes priority only. Actions record work, never grant points.
Agent claims are guided observations, not platform-attested collector results.
Public research remains unassessed context, never personal compromise.

The default loop target is score >=85, coverage >=90 and zero critical findings.
The server computes `target.met`. The agent continues safe useful actions until
that target is met or records specific user/access blockers. Completing an audit
pass below the target must never look like achieving the target.

## Scans and capabilities

`apps/worker` exposes `/api/scans` and `/mcp/scans/:id`. Each anonymous scan has
independent read, agent and owner capabilities, hashed at rest. Read grants only
viewing. Agent grants only that scan's audit operations. Owner can issue a fresh
agent token or delete the scan and stays in the creating browser. Private read
links carry their capability in the fragment, never a server-bound query string.
The browser sends it in Authorization when fetching state. No analytics or third
party runtime scripts are loaded on scan pages.

D1 stores encrypted, schema-validated scan payloads with 30-day retention. Agent
access is limited to seven days and cannot outlive the scan. Scheduled cleanup
removes expired records. Every mutation uses revision compare-and-swap and an
operation UUID for retry safety. Bound body sizes, histories and rate limits.
See [the exact protocol](AGENT-SCAN-CONTRACT.md).

## Agent handoff

The copied prompt identifies the private live link and scoped MCP connection,
then points at `/agent/skill.md`. The canonical source is
`skills/palisade/SKILL.md`. Build packaging copies it alongside the reviewed
CLI/MCP bundles, license notices, checksums and manifest. The CLI's `scan-agent`
mode and stdio `--scan` bridge use the same hosted MCP tools. Direct HTTPS API
operations provide a fallback when the user's agent has no Bun or dynamic MCP.
Installation is never an excuse to stop the audit in the current conversation.

No provider key is required for the workflow. Existing agent tools perform web
search and can use separately authorized platforms. Do not silently send
identifiers to a new provider, fetch stolen data, or treat source text as tool
authorization. Preserve facts, dates, provenance and uncertainty in evidence.

## Retained APIs and local mode

Existing `/api/v1`, `/mcp`, and Better Auth `/api/auth` remain for compatibility.
Existing account audit data is retained separately from anonymous scans. Their
scoped sessions/tokens, encrypted provider keys, monitoring and exports maintain
their prior boundaries. They are not another product screen.

Local CLI state uses private permissions, locking and atomic replacement. The
fixed macOS collector is read-only and limited. Local and hosted workspaces never
silently sync. External agents implement only fixes within their own actual tool
authorization; Palisade MCP itself does not execute arbitrary shell commands or
change account/device settings.

## Deployment and review

Alchemy provisions Cloudflare resources using only the global `default` profile.
Never store Cloudflare tokens in the project or change authentication methods.
The deployment source of application secrets remains outside the checkout;
setup also writes an ignored private `.dev.vars` copy for local development.
Build only explicit public artifacts; never copy secrets or parent-directory
personal evidence.

Use separate builders and critics for substantial changes. Test capability
isolation, provenance, concurrency, expiry and the real CLI/MCP-to-web flow.
Validate the landing handoff and scan states on desktop/mobile, including denied
clipboard access, refresh, disconnection, waiting, blocked and completed scans.
