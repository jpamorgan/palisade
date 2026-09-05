import { afterEach, expect, test } from "bun:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { LocalService } from "@palisade/cli/service";
import { createPalisadeMcpServer, callPalisadeTool } from "../src/server";
const directories: string[] = [];
async function directory() {
  const dir = await mkdtemp(join(tmpdir(), "palisade-mcp-"));
  directories.push(dir);
  return dir;
}
afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((dir) => rm(dir, { recursive: true, force: true })),
  );
});
test("official SDK protocol lists capabilities, records real evidence, and preserves history", async () => {
  const server = createPalisadeMcpServer(new LocalService(await directory()), {
    local: true,
  });
  const client = new Client({ name: "test-client", version: "1.0.0" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  try {
    const listed = await client.listTools();
    expect(listed.tools.some((tool) => tool.name === "scan_mac")).toBe(true);
    expect((await client.listResources()).resources).toHaveLength(2);
    expect((await client.listPrompts()).prompts[0]?.name).toBe(
      "continue-audit",
    );
    const added = await client.callTool({
      name: "add_asset",
      arguments: { kind: "device", label: "Test laptop", critical: true },
    });
    const assetId = (added.structuredContent as any).workspace.assets[0].id;
    const result = await client.callTool({
      name: "record_evidence",
      arguments: {
        checkId: "devices.disk-encryption",
        assetId,
        status: "pass",
        notes: "I verified FileVault is enabled in System Settings.",
      },
    });
    expect(result.isError).not.toBe(true);
    expect((result.structuredContent as any).workspace.evidence[0].method).toBe(
      "guided",
    );
    const invalid = await client.callTool({
      name: "record_evidence",
      arguments: {
        checkId: "devices.disk-encryption",
        assetId,
        status: "pass",
        notes: "I verified the setting.",
        method: "provider",
      },
    });
    expect(invalid.isError).toBe(true);
    const edited = await client.callTool({
      name: "update_asset",
      arguments: { assetId, label: "Renamed test laptop", critical: false },
    });
    expect((edited.structuredContent as any).workspace.assets[0].label).toBe(
      "Renamed test laptop",
    );
    const audit = await client.callTool({ name: "run_audit", arguments: {} });
    expect((audit.structuredContent as any).workspace.snapshots).toHaveLength(
      1,
    );
    const snapshotId = (audit.structuredContent as any).workspace.snapshots[0]
      .id;
    const preferences = await client.callTool({
      name: "update_workspace",
      arguments: {
        revision: (audit.structuredContent as any).revision,
        name: "Updated agent workspace",
        region: "CA",
      },
    });
    expect((preferences.structuredContent as any).workspace.name).toBe(
      "Updated agent workspace",
    );
    const rejectedDelete = await client.callTool({
      name: "remove_snapshot",
      arguments: { snapshotId },
    });
    expect(rejectedDelete.isError).toBe(true);
    const removed = await client.callTool({
      name: "remove_snapshot",
      arguments: { snapshotId, confirmation: "DELETE" },
    });
    expect((removed.structuredContent as any).workspace.snapshots).toHaveLength(
      0,
    );
    await client.callTool({ name: "run_audit", arguments: {} });
    const workspace = await client.readResource({
      uri: "palisade://workspace",
    });
    expect(
      JSON.parse((workspace.contents[0] as any).text).workspace.snapshots,
    ).toHaveLength(1);
  } finally {
    await client.close();
    await server.close();
  }
});
test("scoped hosted server hides local-only and unauthorized tools and refuses direct bypass", async () => {
  let count = 0;
  const service = {
    request: async () => {
      count++;
      return {};
    },
  };
  const server = createPalisadeMcpServer(service, { scopes: ["read"] });
  const client = new Client({ name: "read-only-client", version: "1.0.0" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await server.connect(b);
  await client.connect(a);
  try {
    const tools = (await client.listTools()).tools;
    expect(
      tools.every(
        (tool) =>
          !["scan_mac", "record_evidence", "run_audit"].includes(tool.name),
      ),
    ).toBe(true);
    await expect(
      callPalisadeTool(service, "record_evidence", {}, { scopes: ["read"] }),
    ).rejects.toThrow("not permitted");
    expect(count).toBe(0);
  } finally {
    await client.close();
    await server.close();
  }
});
test("stdio executable completes initialization and tool call without stdout noise", async () => {
  const dir = await directory();
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [resolve(import.meta.dir, "../src/index.ts")],
    env: { PATH: process.env.PATH ?? "", PALISADE_DATA_DIR: dir },
    stderr: "pipe",
  });
  const client = new Client({ name: "stdio-test", version: "1.0.0" });
  try {
    await client.connect(transport);
    const result = await client.callTool({
      name: "get_workspace",
      arguments: {},
    });
    expect((result.structuredContent as any).workspace.schemaVersion).toBe(1);
  } finally {
    await client.close();
  }
}, 15000);

test("detached Bun bundle completes protocol mutations and preserves local state after restart", async () => {
  const detached = await directory();
  const build = await Bun.build({
    entrypoints: [resolve(import.meta.dir, "../src/index.ts")],
    target: "bun",
    outdir: detached,
    naming: "palisade-mcp.js",
  });
  expect(build.success).toBe(true);
  const executable = join(detached, "palisade-mcp.js");
  const options = {
    command: process.execPath,
    args: [executable],
    cwd: detached,
    env: {
      PATH: process.env.PATH ?? "",
      PALISADE_DATA_DIR: join(detached, "state"),
    },
    stderr: "pipe" as const,
  };
  const client = new Client({ name: "bundle-test", version: "1.0.0" });
  try {
    await client.connect(new StdioClientTransport(options));
    const added = await client.callTool({
      name: "add_asset",
      arguments: { kind: "device", label: "Detached synthetic laptop" },
    });
    const assetId = (added.structuredContent as any).workspace.assets[0].id;
    expect(added.isError).not.toBe(true);
    const evidence = await client.callTool({
      name: "record_evidence",
      arguments: {
        checkId: "devices.disk-encryption",
        assetId,
        status: "pass",
        notes: "Synthetic bundle QA verified encryption enabled and complete.",
      },
    });
    expect(evidence.isError).not.toBe(true);
    const audited = await client.callTool({ name: "run_audit", arguments: {} });
    expect((audited.structuredContent as any).workspace.snapshots).toHaveLength(
      1,
    );
  } finally {
    await client.close();
  }
  const restarted = new Client({
    name: "bundle-restart-test",
    version: "1.0.0",
  });
  try {
    await restarted.connect(new StdioClientTransport(options));
    const current = await restarted.callTool({
      name: "get_workspace",
      arguments: {},
    });
    const workspace = (current.structuredContent as any).workspace;
    expect(workspace.assets[0].label).toBe("Detached synthetic laptop");
    expect(workspace.evidence[0].method).toBe("guided");
    expect(workspace.snapshots).toHaveLength(1);
  } finally {
    await restarted.close();
  }
}, 15000);
