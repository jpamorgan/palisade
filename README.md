# Palisade

A private, evidence-led security audit for your digital life. Work through eight
areas, verify the important controls, fix gaps, and return to a dated record of
what changed. Available as an open-source CLI, an MCP server, and a hosted web app.

[Open the hosted app](https://palisade.jpamorgan.workers.dev) ·
[Source and setup](https://github.com/jpamorgan/palisade)

The web app is one grouped checklist. Priority, posture and assessed coverage stay
visible; account setup, history and integrations open only when needed. Visitors
can explore clearly labeled sample data before creating a private account.

## What works in v0.1

- 38 versioned checks covering exposure, sign-in, recovery, devices, networks,
  financial protection, data/backups, and incident readiness.
- Deterministic posture and assessed-coverage scores, per-asset explanations,
  freshness, immutable audit snapshots, and separate remediation progress.
- A read-only macOS collector and guided checks for accounts/devices that do not
  expose suitable APIs. No account or system settings are changed automatically.
- HIBP breach lookup, CISA exploited-vulnerability reports, the public breach
  catalog, and optional Brave public-footprint search. Credentials and explicit
  identifier-disclosure consent are required where applicable.
- Better Auth accounts, passkeys, TOTP/backup codes, scoped expiring API tokens,
  encrypted tenant audit storage, exports, imports, and data deletion.
- Cloudflare Workers, static assets, D1, Queues, Cron, Workers AI, and optional
  Cloudflare Email Service, provisioned with Alchemy.

The app never declares you compromised from a news report. Imported observations
remain unverified until rechecked. A historical breach remains in history after
protective controls are improved. This is an audit and guided-hardening tool;
it does not replace incident forensics, an endpoint security agent, or a provider's
account recovery process.

## Start locally

Install [Bun](https://bun.sh), clone this repository, then:

```sh
git clone https://github.com/jpamorgan/palisade.git
cd palisade
bun install
bun run cli --help
bun run cli init --name "My security"
```

See [CLI and MCP usage](docs/cli.md) for the exact command reference, local state,
provider credentials, remote access, imports, and reports. Local checks and scoring
work without an LLM or hosted account. Private state stays outside this repository
unless you explicitly choose a different path.

Standalone Bun bundles are also provided in
[GitHub releases](https://github.com/jpamorgan/palisade/releases). Run
`bun palisade.js --help`, or configure `bun palisade-mcp.js` as a stdio MCP server.
These bundles do not require a repository checkout or an npm installation.

## Run the web app and API

```sh
bun scripts/setup.ts
bun run --cwd apps/web build
bunx wrangler d1 migrations apply palisade-local --local --config wrangler.jsonc
bun run dev:api
```

In a second terminal:

```sh
bun run dev
```

The API runs on `http://localhost:8787`; the web development server proxies
same-origin API calls to it. The frontend includes a clearly labeled interactive
demo that uses example data stored only in the browser.

`scripts/setup.ts` generates application secrets in
`~/.config/palisade/deployment.json` with private permissions and writes ignored
local `.dev.vars`. It does not read or change Cloudflare credentials. Keep a secure
backup of the deployment secrets: replacing the encryption key makes existing
audit data unreadable, and replacing the auth secret invalidates protected auth
material.

## Deploy entirely on Cloudflare

Palisade uses the globally configured **default Alchemy profile**. It does not
switch authentication methods or copy Cloudflare tokens into the project.

```sh
bun scripts/setup.ts
bun scripts/preflight.ts
bun run deploy
```

The deployment prints its Workers URL. You can set `PALISADE_DOMAIN` for a domain
already managed in the same Cloudflare account. For transactional email, first
onboard a sender domain with Cloudflare Email Service, then set
`PALISADE_EMAIL_FROM` before deployment. Without it, password/passkey/TOTP sign-in
works, while email verification, email password reset, and hosted personal breach
lookups remain explicitly unavailable. Public threat feeds, local audit, guided
checks, and the rest of the platform continue to work.

Hosted HIBP lookup currently supports the verified account email only. Additional
aliases may be inventoried and checked locally with ownership attestation, but
the hosted service does not treat an inventory label as proof of ownership.

Optional hosted AI guidance uses the Cloudflare Workers AI binding. It receives
the chosen check, aggregate score/coverage, and the user's submitted question;
it receives no asset identifiers or raw evidence automatically. It cannot change
state or execute mitigations.

## API and MCP

- REST: `/api/v1/*`, documented at `/openapi.json`.
- Hosted MCP: `/mcp`, using an explicit scoped Bearer token from Settings.
- Local MCP: stdio, with the same check catalog and local evidence store.
- Better Auth: `/api/auth/*`.

The hosted MCP endpoint uses manually configured bearer tokens in this release;
it does not advertise an OAuth authorization flow. Tokens are hashed at rest,
scoped, expire after at most 90 days, and can be revoked in Settings. Tokens cannot
create more tokens or retrieve stored provider keys.

Workspace writes accept `Idempotency-Key`. Replays return the original encrypted
stored response; token-creation replays report that the secret was already shown
and do not issue a second token. Preference changes also require the current
workspace revision to detect concurrent edits.

Daily monitoring refreshes public threat context and re-evaluates freshness; it
does not rerun local device checks, privately query HIBP, or send email alerts.
Saved snapshots are explicit. Hosted workspaces have a 1 MB budget; export any
history you wish to keep before removing older snapshots from Audit history.
Account deletion is also available through Better Auth's `/api/auth/delete-user`
endpoint with an authenticated session and password (or a fresh session), and
cascades to the account's audit data, integrations, and tokens.

## Verification and contribution

```sh
bun test
bun run typecheck
bun run build
```

To verify a test deployment end to end, run
`bun scripts/smoke.ts https://YOUR_HOST`. It creates synthetic data, exercises
registration, audit persistence, scopes, hosted MCP, public feeds and Workers AI,
then deletes the entire synthetic account. Do not point a smoke test at a host
you do not operate.

Core, transport, and API tests cover scoring, provenance, stale observations,
provider failures, real MCP stdio, authentication, tenant isolation, and token
permissions. See [methodology](docs/methodology.md), [security](SECURITY.md), and
[contribution guidance](CONTRIBUTING.md).

MIT licensed. This repository contains no personal audit evidence or credentials.
