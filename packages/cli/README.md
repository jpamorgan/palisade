# Palisade CLI

An open-source, local-first personal security checklist with an evidence ledger, deterministic scoring, repeatable audits, and optional hosted API access. Requires Bun 1.3 or newer.

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
