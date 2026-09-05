#!/usr/bin/env bun
// Keep the shared Zod engine initialized before SDK schema construction in Bun bundles.
import { createService } from "@palisade/cli/service";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createPalisadeMcpServer } from "./server";
const host = process.env.PALISADE_HOST;
try {
  const service = createService({
    host,
    token: process.env.PALISADE_TOKEN,
    dataDir: process.env.PALISADE_DATA_DIR,
  });
  const server = createPalisadeMcpServer(service, { local: !host });
  await server.connect(new StdioServerTransport());
  const shutdown = async () => {
    await server.close();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
} catch (error) {
  console.error(
    "Palisade MCP: " +
      (error instanceof Error ? error.message : "Could not start."),
  );
  process.exit(1);
}
