# Architecture and extension contract

Palisade has one runtime-neutral TypeScript audit engine, with three clients:
React web, a Bun CLI, and MCP. The engine lives in `packages/core`; it owns the
catalog, validation, scoring, evidence provenance, recovery graph and provider
adapters. Clients must not implement alternative scoring logic.

## Product flow

The primary interface is a grouped checklist: overall posture and assessment
coverage, ranked next checks, and eight areas with progress bars. Users open a
check to verify it, record a gap, or work through its mitigation. Account/device
inventory and settings open as on-demand panels. Exposure details and saved
history stay in a secondary menu. There is one canonical app screen at `/`, with
authentication in a dialog and only essential password recovery separated.
Completing a mitigation never marks evidence verified.

## Portable state

A schema-versioned workspace holds assets, evidence, remediation actions, immutable
saved snapshots, threat context and preferences. Each record has a stable ID.
Core mutations return a new workspace. Asset identifier/recovery changes preserve
history and invalidate affected current evidence. All explicitly added assets
count; importance affects priority only.

The evaluation includes a nullable posture score, assessed coverage, category and
per-asset results, reasons, findings, an evaluation timestamp, and catalog/scoring
versions. The same state, versions and timestamp must produce the same result.
See [methodology](methodology.md) for exact scoring and applicability rules.

Imports validate before merging and cannot establish trusted evidence or rewrite
local history. Provider or local provenance is assigned only by the matching
collector, never by a generic evidence submission.

## Hosted service

`apps/worker` is a Hono Cloudflare Worker. Better Auth handles accounts, sessions,
passkeys and TOTP. D1 stores tenant-scoped account data, encrypted audit payloads,
encrypted provider keys, hashed API tokens, activity and concurrency metadata.
Every persisted workspace must pass the shared core schema. Audit changes use
optimistic compare-and-swap; preference edits additionally require a revision.

REST lives at `/api/v1`. Request schemas in `apps/worker/src/contracts.ts` are
shared with the generated `/openapi.json` document. Workspace mutations return
`{ workspace, evaluation, revision }`. The hosted `/mcp` endpoint uses the same
service operations and requires an explicit scoped token. Tokens cannot create
other tokens or access stored provider credentials.

Workers serve the React static assets on the same origin. Cron and Queues refresh
public threat context for opted-in workspaces. This re-evaluates freshness without
creating daily saved snapshots. Optional Workers AI explains catalog guidance and
cannot execute actions. Optional Cloudflare Email Service enables ownership
verification and email password reset.

## Local service

The CLI uses a private, locked, atomically replaced JSON workspace. Local mode
needs no hosted account or LLM. A fixed read-only macOS collector can attach
appropriately limited local evidence. Stdio MCP uses the same local service; only
local MCP exposes device collection. Sync is explicit, never automatic.

## Provider boundaries

Use fixed allowlisted endpoints, bounded responses, timeouts and no credentialed
redirects. Disclose an email to HIBP or a search term to Brave only with explicit
consent. Hosted HIBP checks the verified login email only. Public feeds establish
context, never personal compromise. Matches must remain bound to the identifier
that was actually queried, including when an asset changes during a scan.

## Deployment and verification

Alchemy provisions Workers/assets, D1/migrations, Queues, Cron, Workers AI and
optional Cloudflare email. Use the existing global `default` Alchemy profile;
never copy Cloudflare credentials into this repository or change auth methods.
Application secrets live outside the checkout and are encrypted in Alchemy state.

Run `bun test`, `bun run typecheck`, and `bun run build`. Tests cover the shared
engine, real MCP protocol, local concurrency, API permissions and tenant isolation,
TOTP/backup codes, and browser cache isolation. `scripts/smoke.ts` exercises a live
test deployment with synthetic data and deletes the test account afterward.
