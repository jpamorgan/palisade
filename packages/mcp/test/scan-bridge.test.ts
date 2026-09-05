import { afterAll, beforeAll, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { z } from "zod";

const token = "pal_synthetic_agent_bridge_token_123456789012345";
const scanId = "00000000-0000-4000-8000-000000000001";
let directory: string, cliPath: string, mcpPath: string;
beforeAll(async () => {
  directory = await mkdtemp(join(tmpdir(), "palisade-agent-bridge-"));
  cliPath = join(directory, "cli", "index.js");
  mcpPath = join(directory, "mcp", "index.js");
  for (const [entry, outdir] of [
    ["../../cli/src/index.ts", "cli"],
    ["../src/index.ts", "mcp"],
  ]) {
    const build = Bun.spawn(
      [
        process.execPath,
        "build",
        resolve(import.meta.dir, entry!),
        "--target=bun",
        "--outdir",
        join(directory, outdir!),
      ],
      { stdout: "pipe", stderr: "pipe" },
    );
    const [code, errors] = await Promise.all([
      build.exited,
      new Response(build.stderr).text(),
    ]);
    expect(errors).not.toContain("error:");
    expect(code).toBe(0);
  }
});
afterAll(async () => {
  await rm(directory, { recursive: true, force: true });
});

function fixture() {
  let revision = 0;
  const messages: string[] = [];
  const operations = new Set<string>();
  const requests: string[] = [];
  let redirect = false;
  let redirectHits = 0;
  const server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(request) {
      const url = new URL(request.url);
      requests.push(url.pathname);
      if (url.pathname === "/redirect-target") {
        redirectHits++;
        return new Response("Unexpected redirect");
      }
      if (url.pathname !== `/mcp/scans/${scanId}`)
        return new Response(null, { status: 404 });
      if (redirect)
        return new Response(null, {
          status: 307,
          headers: { location: "/redirect-target" },
        });
      if (request.headers.get("authorization") !== `Bearer ${token}`)
        return new Response(
          `Rejected ${request.headers.get("authorization")}`,
          { status: 401 },
        );
      if (request.method !== "POST") return new Response(null, { status: 405 });
      const mcp = new McpServer(
        { name: "synthetic-scan", version: "1.0" },
        {
          instructions:
            "Read get_scan, then publish verified observations with revision and operationId.",
        },
      );
      const state = () => ({
        revision,
        messages,
        scan: { id: scanId },
        echo: token,
      });
      const result = () => ({
        content: [{ type: "text" as const, text: JSON.stringify(state()) }],
        structuredContent: state(),
      });
      mcp.registerTool(
        "get_scan",
        { inputSchema: z.object({}).strict() },
        result,
      );
      mcp.registerTool(
        "report_progress",
        {
          inputSchema: z
            .object({
              revision: z.number().int(),
              operationId: z.string().uuid(),
              message: z.string(),
            })
            .strict(),
        },
        (args) => {
          if (!operations.has(args.operationId)) {
            if (args.revision !== revision)
              return {
                isError: true,
                content: [
                  {
                    type: "text",
                    text: `Revision conflict; accidental token echo ${token}`,
                  },
                ],
              };
            operations.add(args.operationId);
            messages.push(args.message);
            revision++;
          }
          return result();
        },
      );
      mcp.registerResource("scan", "palisade://scan", {}, (uri) => ({
        contents: [{ uri: uri.href, text: JSON.stringify(state()) }],
      }));
      mcp.registerPrompt("continue", {}, () => ({
        messages: [
          {
            role: "user",
            content: { type: "text", text: "Continue the audit." },
          },
        ],
      }));
      const transport = new WebStandardStreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });
      await mcp.connect(transport);
      const response = await transport.handleRequest(request);
      await mcp.close();
      return response;
    },
  });
  return {
    env: {
      PATH: process.env.PATH ?? "",
      PALISADE_SCAN_URL: `http://127.0.0.1:${server.port}/scan/${scanId}`,
      PALISADE_AGENT_TOKEN: token,
    },
    messages,
    requests,
    redirect: () => {
      redirect = true;
    },
    redirectHits: () => redirectHits,
    stop: () => server.stop(true),
  };
}

async function command(
  env: Record<string, string>,
  args: string[],
  input?: string,
) {
  const child = Bun.spawn([process.execPath, cliPath, "scan-agent", ...args], {
    cwd: directory,
    env,
    stdout: "pipe",
    stderr: "pipe",
    stdin: input === undefined ? "ignore" : new Response(input),
  });
  const [stdout, stderr, code] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  return { stdout, stderr, code };
}

test("detached CLI immediately discovers MCP, writes over HTTP, and resumes in a new process", async () => {
  const host = fixture();
  try {
    const listed = await command(host.env, ["tools"]);
    expect(listed.code).toBe(0);
    const discovery = JSON.parse(listed.stdout);
    expect(discovery.instructions).toContain("verified observations");
    expect(discovery.tools.map((tool: any) => tool.name)).toEqual([
      "get_scan",
      "report_progress",
    ]);
    const input = {
      revision: 0,
      operationId: crypto.randomUUID(),
      message: "Checking synthetic account recovery.",
    };
    const written = await command(
      host.env,
      ["call", "report_progress", "--input", "-"],
      JSON.stringify(input),
    );
    expect(written.code).toBe(0);
    expect(JSON.parse(written.stdout).structuredContent.revision).toBe(1);
    expect(written.stdout).not.toContain(token);
    const restarted = await command(host.env, ["call", "get_scan"]);
    expect(JSON.parse(restarted.stdout).structuredContent.messages).toEqual([
      input.message,
    ]);
    const retried = await command(
      host.env,
      ["call", "report_progress", "--input", "-"],
      JSON.stringify(input),
    );
    expect(retried.code).toBe(0);
    expect(host.messages).toHaveLength(1);
    const resource = await command(host.env, ["read", "palisade://scan"]);
    expect(resource.code).toBe(0);
    expect(
      JSON.parse(JSON.parse(resource.stdout).contents[0].text).revision,
    ).toBe(1);
    expect(resource.stdout).not.toContain(token);
    const conflicting = await command(
      host.env,
      ["call", "report_progress", "--input", "-"],
      JSON.stringify({ ...input, operationId: crypto.randomUUID() }),
    );
    expect(conflicting.code).toBe(1);
    expect(conflicting.stdout).toContain("Revision conflict");
    expect(conflicting.stdout).not.toContain(token);
    expect(host.requests.every((path) => path === `/mcp/scans/${scanId}`)).toBe(
      true,
    );
  } finally {
    host.stop();
  }
}, 30_000);

test("detached scan CLI protects auth, rejects malformed input and never follows redirects", async () => {
  const host = fixture();
  try {
    const denied = await command(
      {
        ...host.env,
        PALISADE_AGENT_TOKEN: "pal_wrong_synthetic_agent_token_123456789012345",
      },
      ["tools"],
    );
    expect(denied.code).toBe(3);
    expect(denied.stdout).toBe("");
    expect(denied.stderr).not.toContain("pal_wrong");
    const malformed = await command(
      host.env,
      ["call", "report_progress", "--input", "-"],
      "[]",
    );
    expect(malformed.code).toBe(2);
    const oversized = await command(
      host.env,
      ["call", "report_progress", "--input", "-"],
      JSON.stringify({ message: "x".repeat(65_536) }),
    );
    expect(oversized.code).toBe(2);
    const unknown = await command(host.env, ["call", "unknown_tool"]);
    expect(unknown.code).toBe(1);
    host.redirect();
    const redirected = await command(host.env, ["tools"]);
    expect(redirected.code).toBe(1);
    expect(redirected.stderr).not.toContain(token);
    expect(host.redirectHits()).toBe(0);
  } finally {
    host.stop();
  }
}, 30_000);

test("detached stdio bridge proxies advertised tools/resources/prompts and retains HTTP scan state after restart", async () => {
  const host = fixture();
  const options = {
    command: process.execPath,
    args: [mcpPath, "--scan"],
    cwd: directory,
    env: host.env,
    stderr: "pipe" as const,
  };
  const client = new Client({ name: "synthetic-agent", version: "1.0" });
  try {
    await client.connect(new StdioClientTransport(options));
    expect((await client.listTools()).tools).toHaveLength(2);
    expect((await client.listResources()).resources).toHaveLength(1);
    expect(
      (await client.listResourceTemplates()).resourceTemplates,
    ).toHaveLength(0);
    expect((await client.listPrompts()).prompts[0]!.name).toBe("continue");
    expect(
      (await client.getPrompt({ name: "continue" })).messages,
    ).toHaveLength(1);
    const result = await client.callTool({
      name: "report_progress",
      arguments: {
        revision: 0,
        operationId: crypto.randomUUID(),
        message: "Synthetic stdio audit progress.",
      },
    });
    expect((result.structuredContent as any).revision).toBe(1);
    expect(JSON.stringify(result)).not.toContain(token);
  } finally {
    await client.close();
  }
  const restarted = new Client({
    name: "synthetic-agent-resumed",
    version: "1.0",
  });
  try {
    await restarted.connect(new StdioClientTransport(options));
    const result = await restarted.callTool({
      name: "get_scan",
      arguments: {},
    });
    expect((result.structuredContent as any).messages).toEqual([
      "Synthetic stdio audit progress.",
    ]);
    expect(
      JSON.stringify(await restarted.readResource({ uri: "palisade://scan" })),
    ).not.toContain(token);
  } finally {
    await restarted.close();
    host.stop();
  }
}, 30_000);
