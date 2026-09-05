# Palisade MCP

The official MCP TypeScript SDK powers local audits, capability-protected live scans, and the existing authenticated workspace API. Each uses the same deterministic audit engine.

## Live scan connection

The copied landing-page prompt supplies a scan-specific MCP URL and agent token. A client with dynamic remote MCP support can connect directly to that URL using a Bearer authorization header. Keep the token in the client's secret/environment mechanism; never put it in a URL or checked-in configuration.

For stdio clients, run the standalone bundle with the token and clean scan URL supplied through `PALISADE_AGENT_TOKEN` and `PALISADE_SCAN_URL`:

```sh
bun /path/to/palisade-mcp.js --scan
```

The bridge discovers and forwards this scan's advertised tools, resources and prompts, including their schemas. It never stores a token or creates local audit state. Results update the same scan the user is viewing. Process restart reconnects to the current hosted state. Mutations use the revision and idempotency rules returned by tool discovery; a transport error does not prove a write was rolled back.

If an agent cannot add MCP servers during its current turn, use `bun /path/to/palisade.js scan-agent tools` and `scan-agent call TOOL --input -` instead. That CLI invokes the same MCP tools without a restart. The agent performs web research and safe remediation with its existing tools; this bridge neither needs a search provider key nor executes mitigation commands.

## Local audit connection

Local stdio configuration, after `bun install` at the repository root:

```json
{
  "mcpServers": {
    "palisade": {
      "command": "bun",
      "args": ["/ABSOLUTE/PATH/TO/platform/packages/mcp/src/index.ts"],
      "env": { "PALISADE_DATA_DIR": "/ABSOLUTE/PATH/TO/private-palisade-state" }
    }
  }
}
```

The directory must be dedicated to Palisade. Defaults to `~/.palisade`, shared with the CLI. Stdout is reserved for MCP; startup diagnostics use stderr. Start with `get_catalog` and `get_workspace`. The server also offers the `continue-audit` prompt and `palisade://catalog` / `palisade://workspace` resources.

Build a standalone Bun bundle with `bun run --cwd packages/mcp build` from the repository root. `packages/mcp/dist/index.js` includes its JavaScript dependencies and can be copied outside the checkout; Bun remains required. Use that file's absolute path in the configuration above. The detached-bundle protocol test verifies initialization, evidence, audit history, and persistence across a process restart without a repository or `node_modules` beside the bundle.

## Existing authenticated workspace connection

Existing account/API clients can continue using `https://YOUR_HOST/mcp` with a scoped API token. Alternatively, use the stdio entry point with `PALISADE_HOST` and `PALISADE_TOKEN` supplied through your client's secret/environment mechanism. Never commit a token to an MCP configuration file. New landing-page scans use the separate connection above.

The hosted server hides local Mac collection. Read/write/scan token scopes filter available tools and are also enforced at the service layer. No MCP tool changes device settings or account credentials. Provider queries require explicit consent, and hosted HIBP queries require verified ownership. Importing evidence cannot manufacture provider trust.

Worker integration:

```ts
import { createPalisadeMcpServer } from "@palisade/mcp";
const server = createPalisadeMcpServer(authenticatedService, {
  scopes: ["read", "write", "scan"],
});
```

`authenticatedService.request(method, path, body)` dispatches API operations with a path relative to `/api/v1`. The exported server and tool modules do not import filesystem APIs. Authentication, tenant isolation, and transport handling belong to the host. See [the official SDK server documentation](https://github.com/modelcontextprotocol/typescript-sdk/blob/v1.x/docs/server.md).
