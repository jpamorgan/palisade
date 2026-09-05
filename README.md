# Palisade

**Your agent does the audit. One live page shows where you stand.**

[Open Palisade](https://palisade.jpamorgan.workers.dev) ·
[CLI + MCP downloads](https://github.com/jpamorgan/palisade/releases)

1. Open the site and copy the agent prompt.
2. Paste it into Codex, Claude, or another agent with tools.
3. Watch the private scan page update while the agent checks, safely fixes, and
   re-verifies your security.

There are two product routes: the landing page and `/scan/:id`. No account,
provider setup, dashboard, or search API key is needed. Your agent uses its
existing web search, browser, local tools, and authorized services. The prompt
connects it to the scan's MCP endpoint, with a CLI or HTTP fallback that works in
the current conversation even when adding MCP normally requires a restart.

## What the audit measures

38 checks cover exposure, accounts, recovery, devices, networks, financial
protection, data/backups, and incident response. One versioned engine calculates
posture and assessment coverage for the web, CLI, and MCP. Unknown, stale,
conflicting, and imported evidence stay explicit. There is no score before any
assessment; a completed action never passes a check without new verification.

The default agent loop targets **85/100 posture, 90% coverage, and no critical
findings**. It inventories the relevant assets, prioritizes important gaps,
implements bounded reversible fixes within the user's authorization, verifies
again, and publishes each result. It continues independent safe work around
blockers. If access or a user decision is needed, it says so and pauses honestly.
The target is an audit completion policy, not a calibrated attack probability or
a guarantee of safety. Public breach news never establishes personal compromise.

Read the [agent skill](skills/palisade/SKILL.md) and
[scoring methodology](docs/methodology.md).

## Private scans

Scans last 30 days. A private viewing link grants read access; keep it private.
An independent agent credential can read/update that one scan for up to seven
days. The creating browser retains a separate owner credential for issuing a
fresh agent prompt and deleting the scan. The agent never receives owner access.
Clearing that browser's local storage loses owner access; the viewing link still
works until expiry. A reader cannot change the score or mint an agent token.

Payloads are encrypted at rest with scan-separated keys on Cloudflare. This is
server-side encryption, not end-to-end encryption. Do not submit passwords,
recovery codes, authentication cookies, identity-document numbers, or private
keys. See [security boundaries](SECURITY.md).

## Use the agent bridge

The hosted origin serves `/agent/skill.md`, `/agent/manifest.json`, and standalone
Bun bundles. Verify a downloaded bundle against the manifest's SHA-256 first.
With `PALISADE_SCAN_URL` and `PALISADE_AGENT_TOKEN` supplied in the subprocess
environment:

```sh
bun palisade.js scan-agent tools
bun palisade.js scan-agent call get_scan
bun palisade.js scan-agent call report_progress --input - <<'JSON'
{"revision":0,"operationId":"REPLACE-WITH-A-FRESH-UUID","status":"running","phase":"Checking devices","message":"Verifying the device protections available to this agent."}
JSON
```

Use the latest returned revision, not the example's zero. For a persistent stdio
MCP client, run `bun /absolute/path/palisade-mcp.js --scan` with the same two
environment variables. Direct streamable HTTP MCP is at `/mcp/scans/:id` with an
Authorization bearer header. No OAuth or application restart is required for the
HTTP/CLI fallback. See [the scan protocol](docs/AGENT-SCAN-CONTRACT.md).

## Use the open-source CLI locally

Local audits remain available without a hosted scan or LLM:

```sh
git clone https://github.com/jpamorgan/palisade.git
cd palisade
bun install
bun run cli init --name "My security"
bun run cli --help
```

The local CLI stores a private workspace and offers a fixed read-only macOS
collector. Run `bun run mcp` for local stdio MCP. See the
[CLI guide](docs/cli.md) and [MCP guide](packages/mcp/README.md).
Existing v1 account APIs, Better Auth, and explicitly configured provider
adapters remain compatible for existing clients; they are not part of the new
web onboarding. Their data is not deleted by this UI change. Private HIBP access
still needs an authorized service or the official user-facing verification flow;
missing access remains unknown rather than blocking other checks.

## Develop and deploy

Requires [Bun](https://bun.sh) 1.4.0 or newer.

```sh
bun install
bun scripts/setup.ts
bun run build
bunx wrangler d1 migrations apply palisade-local --local --config wrangler.jsonc
bun run dev:api
```

The built app is available on `http://localhost:8787`. For hot reload, run
`bun run dev` in a second terminal; Vite proxies the API to port 8787. The full
build packages the CLI/MCP and canonical skill before building the web assets.

Everything hosted runs on Cloudflare: Workers, static assets, D1, and scheduled
expiry cleanup. Existing optional account monitoring uses Queues/Cron, and
existing account features retain Workers AI and optional Cloudflare email.
Infrastructure is provisioned through Alchemy using the globally configured
**default** profile exclusively:

```sh
bun scripts/preflight.ts
bun run deploy
```

Do not add Cloudflare credentials to this repository or switch authentication
methods. Application secrets are generated outside the checkout in
`~/.config/palisade/deployment.json` with private permissions. Keep a secure
backup: replacing the encryption key makes existing payloads unreadable.
`PALISADE_DOMAIN` may select a domain already managed in that Cloudflare account.
The agent-led scan flow does not require an email sender, HIBP key, Brave key, or
hosted AI configuration.

## Verify

```sh
bun test
bun run typecheck
bun run build
bun scripts/scan-smoke.ts http://localhost:8787
```

The scan smoke test creates only synthetic data, exercises the actual hosted MCP
handoff and score updates, and deletes its scans. Run it only against a deployment
you operate. `scripts/smoke.ts` additionally tests retained v1 account APIs.

Meaningful tests cover scoring and evidence authority, capability isolation,
expiry, concurrent writes and idempotency, detached MCP/CLI, and the two-route
web experience. Use synthetic data when contributing. MIT licensed.
