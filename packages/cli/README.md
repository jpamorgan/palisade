# Palisade CLI

An open-source personal security audit CLI. An agent can publish to a live hosted scan immediately, or keep a complete audit locally. Both use the same evidence ledger and deterministic scoring. Requires Bun 1.3 or newer.

## Connect an agent to a live scan

Copy the prompt from the Palisade landing page into your agent. It contains this scan's connection details and workflow. Set `PALISADE_SCAN_URL` (without its `#key` fragment) and `PALISADE_AGENT_TOKEN` through the process environment. Keep the agent token out of arguments, shell history, notes, and checked-in configuration.

```sh
bun /path/to/palisade.js scan-agent tools
bun /path/to/palisade.js scan-agent call get_scan
bun /path/to/palisade.js scan-agent call get_catalog
```

This uses the official MCP client over HTTP in the current shell. It does not require adding a server to your agent configuration, restarting the agent, an account, or a hosted search API key. Use the agent's existing web search, browser, and authorized local tools for the audit. Each tool returns the live scan state, including score, coverage, and revision. The user watches that same scan in the web app.

Use the schemas returned by `tools` to build arguments, then pipe a JSON object into `scan-agent call TOOL --input -`, or pass a regular JSON file with `--input FILE`. A write needs the last observed revision and a fresh UUID `operationId`. After an interrupted request, read the scan and retry the **same operation ID and identical arguments**; after a confirmed revision conflict, read the new revision and use a new operation ID. The CLI never automatically retries a write or changes security settings.

`scan-agent read URI` can read resources if the server advertises them. `scan-agent --help` describes command behavior and exit codes. Scan mode creates no local audit files. For a stdio MCP connection use the companion `palisade-mcp --scan` bundle with those same environment variables.

## Local audits

From this repository:

```sh
bun install
bun run cli init --name "My security audit"
bun run cli assets add --kind device --label "My Mac"
bun run cli checks devices.disk-encryption
bun run cli status
```

Use the returned asset ID to scope evidence or a consented scan:

```sh
bun run cli scan mac --asset YOUR_ASSET_ID --consent
bun run cli audit
bun run cli report --out ./security-report.html
bun run cli --help
```

`--consent` confirms the selected asset belongs to you or that you have permission to audit it. The Mac collector runs five fixed read-only commands. It never reads passwords, browser data, vaults, cookies, private documents, or environment files. FileVault status can verify disk encryption; an enabled firewall still requires manual review of inbound exceptions. Gatekeeper, SIP, and update checking are contextual observations, not substitutes for the full checklist.

Local state is saved under `~/.palisade/workspace.json` with owner-only permissions. Choose another dedicated directory using `--data-dir`. Your audit data is not encrypted by the CLI; protect the device and its backups. Provider keys and hosted API tokens are read from the process environment and are never saved in the workspace. Do not put secret values in notes.

[Complete command guide](../../docs/cli.md). MIT licensed. These packages are source-ready in this repository; they have not been published to npm.
