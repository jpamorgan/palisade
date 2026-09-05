# Palisade MCP

The official MCP TypeScript SDK powers both a persistent local stdio server and the hosted platform's Streamable HTTP endpoint. The same tool definitions and security rules apply to both.

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

For hosted access, connect an MCP client that supports custom bearer authorization to `https://YOUR_HOST/mcp`. Create a scoped API token in the web platform. Alternatively, use the stdio entry point with `PALISADE_HOST` and `PALISADE_TOKEN` supplied through your client's secret/environment mechanism. Never commit a token to an MCP configuration file.

The hosted server hides local Mac collection. Read/write/scan token scopes filter available tools and are also enforced at the service layer. No MCP tool changes device settings or account credentials. Provider queries require explicit consent, and hosted HIBP queries require verified ownership. Importing evidence cannot manufacture provider trust.

Worker integration:

```ts
import { createPalisadeMcpServer } from "@palisade/mcp";
const server = createPalisadeMcpServer(authenticatedService, {
  scopes: ["read", "write", "scan"],
});
```

`authenticatedService.request(method, path, body)` dispatches API operations with a path relative to `/api/v1`. The exported server and tool modules do not import filesystem APIs. Authentication, tenant isolation, and transport handling belong to the host. See [the official SDK server documentation](https://github.com/modelcontextprotocol/typescript-sdk/blob/v1.x/docs/server.md).
