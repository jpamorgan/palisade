# CLI and MCP guide

Palisade's local CLI, stdio MCP server, and hosted API share the versioned core engine. Local operation needs no account or LLM. Hosted access adds a private account and scoped tokens. Local scan observations are never uploaded automatically.

## Get started

Requires Bun 1.3 or newer. Run from the `platform` repository:

```sh
bun install
bun run cli init --name "My security audit"
bun run cli assets add --kind email --label "Primary email" --value "you@example.com" --critical
bun run cli assets add --kind device --label "My Mac" --critical
bun run cli checks
bun run cli status
```

Asset kinds: `email`, `phone`, `device`, `domain`, `financial`, `password_manager`, `identity`, and `network`. A label is sufficient for most checks. Email values must be valid addresses; identity-document numbers are refused. IDs printed by `assets list` are stable within the workspace.

Update labels, identifiers, and recovery relationships without deleting history:

```sh
bun run cli assets edit YOUR_EMAIL_ID --recovery YOUR_PHONE_ID,YOUR_BACKUP_EMAIL_ID
bun run cli assets edit YOUR_DEVICE_ID --label "Personal laptop" --not-critical
```

`--recovery ""` clears recorded connections; `--value ""` clears an optional identifier. Omitted fields stay unchanged. Asset kind and ID stay fixed. Identifier changes reopen affected checks, and recovery changes reopen related recovery checks. Cosmetic label or importance changes retain evidence. Every explicitly added asset still counts toward its applicable checks; the importance flag is not a scoring exclusion.

## Verify, mitigate, re-audit

```sh
bun run cli checks devices.disk-encryption
bun run cli evidence add devices.disk-encryption --asset YOUR_DEVICE_ID --status pass --notes "Verified FileVault is enabled and encryption is complete in System Settings."
bun run cli actions plan devices.firewall --asset YOUR_DEVICE_ID
bun run cli actions complete devices.firewall --asset YOUR_DEVICE_ID --notes "Reviewed configuration; verification is next."
bun run cli audit
bun run cli history
```

Evidence statuses are `pass`, `partial`, `fail`, `unknown`, and `not_applicable`. Follow each check's verification requirement; partial credit is valid only when the catalog defines it. Resolved guided evidence requires concrete notes, at least 16 characters. `--observed-at` accepts an ISO timestamp for an actual past observation; it cannot be in the future. Recording an action has no effect on evidence or scoring. An audit re-evaluates evidence freshness and saves an immutable snapshot; it does not rerun providers or refresh old observations.

`audit --fail-under 70 --json` returns exit code 2 if the score is below 70 or remains unassessed. Coverage remains an independent field. Exit codes: 0 successful operation, 1 operation/provider failure, 2 usage/validation/threshold failure, 3 hosted authentication/authorization failure. JSON successes go to stdout and errors to stderr. Provider receipts report unavailable or failed services without passing checks.

Update a workspace name or region, or opt into hosted public-threat monitoring:

```sh
bun run cli workspace set --name "Personal audit" --region US
bun run cli workspace set --monitoring --host https://YOUR_HOST
```

Workspace updates fetch the current revision before writing, so hosted read+write scopes are required. Local mode runs on demand and refuses to enable monitoring. To reclaim history capacity, `audit delete SNAPSHOT_ID --confirm` permanently deletes one snapshot while preserving current evidence and other snapshots. Export any history you wish to retain first.

## Optional scans

```sh
bun run cli scan mac --asset YOUR_DEVICE_ID --consent
bun run cli scan hibp --asset YOUR_EMAIL_ID --consent
bun run cli scan footprint --asset YOUR_PUBLIC_IDENTIFIER_ASSET_ID --consent
bun run cli scan threats
bun run cli integrations
```

The Mac collector runs only on macOS. It uses fixed argument lists with `execFile`, no shell execution and no privilege elevation. Commands: `fdesetup status`, `socketfilterfw --getglobalstate`, `spctl --status`, `csrutil status`, and `defaults read` of the system's `AutomaticCheckEnabled` preference. Each command has an 8-second timeout and 16 KiB output cap. Raw command output is not persisted. Unknown or unavailable output is not passing evidence. FileVault can verify encryption; firewall enabled status leaves the check unknown until exceptions are reviewed. Gatekeeper, SIP, and update-checking status are context only.

`HIBP_API_KEY` and `BRAVE_SEARCH_API_KEY` are optional process environment variables in local mode. Supply them through your preferred secret manager, not command arguments, evidence notes, or committed files. HIBP sends the selected email address to Have I Been Pwned. Footprint sends the stored asset value, or the public name label of an identity asset, to Brave Search; each result is an unconfirmed identity match. Result count never becomes a prominence score. Public threat feeds send no personal identifier and do not establish that you are affected. Local `--consent` is your assertion of ownership or authorization. Hosted HIBP additionally enforces verified ownership.

## Private storage and portability

```sh
bun run cli export --out ./audit.json
bun run cli import ./audit.json
bun run cli report --out ./audit.html
```

The default dedicated directory is `~/.palisade`; override with `--data-dir` or `PALISADE_DATA_DIR`. Directory mode is 0700 and workspace mode 0600. Writes use an exclusive cross-process lock, validation, fsync, and atomic rename. If the process is killed during a write, a lock may remain: first confirm no Palisade process is running, then remove the `.write-lock` directory. A malformed workspace is preserved, never reset silently. Restore a known-good export by importing into a new dedicated data directory.

Exports and reports are owner-readable/writable files. Existing destinations require explicit `--force`; symlink destinations are refused. Export JSON includes private identifiers, notes, and audit history. The standalone HTML checklist includes the workspace name, asset labels, and evaluated reasons (which can include verification notes), has no scripts, and makes no external requests. Protect these files and backups; filesystem permissions are not encryption.

Import merges assets and records, preserves existing local history, and marks incoming evidence as imported. Imported snapshots are not accepted as trusted local score history. Imported actions become proposals. Reverify relevant controls to earn points. `assets remove ID --confirm` removes that asset and its current evidence from scope while keeping historical snapshots.

## Hosted access and sync

Create a hosted account and a scoped API token in Settings. Supply `PALISADE_TOKEN` through your secret environment mechanism, then:

```sh
bun run cli status --host https://YOUR_HOST --json
bun run cli audit --host https://YOUR_HOST
bun run cli sync push --host https://YOUR_HOST
bun run cli sync pull --host https://YOUR_HOST
```

`--host` or `PALISADE_HOST` selects remote mode. HTTPS is required except loopback HTTP for local development. Redirects are refused so bearer tokens cannot follow a redirect. No token is persisted. `sync push` explicitly sends your local export to the host; `sync pull` explicitly merges the hosted export into local state. Neither replaces the destination workspace, and imported evidence still needs reverification. Hosted workspaces have a 1 MB compact-JSON limit; large local imports may be rejected with an actionable capacity error. Export a backup and remove selected older snapshots when you need to reclaim history space. Mac collection runs locally; use explicit sync after reviewing its results. HIBP/Brave keys for hosted mode are configured in the web UI.

## Agent access

See [MCP setup](../packages/mcp/README.md) for local stdio, hosted Streamable HTTP, resources, prompts, and scoped tools. The shared tool set supports catalog discovery, workspace reads and preference updates, adding and editing assets, guided evidence, mitigation actions, audit snapshots and explicit snapshot deletion, provider availability, consented HIBP and footprint scans, threat-feed refresh, and import/export. Only local stdio exposes Mac collection. The optional [Palisade skill](../skills/palisade/SKILL.md) teaches the evidence/mitigation workflow.

For automation, prefer MCP or JSON CLI output. Basic collection and scoring do not require an LLM. As with any cloud agent, information returned to an MCP client may be sent to that client's model provider; choose the client and workspace deliberately.
