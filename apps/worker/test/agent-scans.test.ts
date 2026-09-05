import { afterAll, beforeEach, describe, expect, test } from "bun:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import worker, { app } from "../src/index";
import {
  CHECKS,
  evaluateWorkspace,
  addAsset,
  recordEvidence,
} from "@palisade/core";
import { testDatabase } from "../../../tests/d1";
import { decrypt, encrypt } from "../src/crypto";
import type { Env } from "../src/env";

const { db, binding } = testDatabase();
const env: Env = {
  DB: binding,
  APP_URL: "http://localhost:8787",
  BETTER_AUTH_SECRET: "scan-test-only-auth-secret-with-32-characters",
  DATA_ENCRYPTION_KEY: "scan-test-only-encryption-secret-with-32-characters",
  ASSETS: {
    fetch: async () => new Response("static assets"),
  } as unknown as Fetcher,
};
const pending: Promise<unknown>[] = [];
const ctx = {
  waitUntil: (promise: Promise<unknown>) => pending.push(promise),
  passThroughOnException() {},
} as unknown as ExecutionContext;
async function request(
  path: string,
  method = "GET",
  body?: unknown,
  token?: string,
  origin?: string,
) {
  const headers = new Headers({ "cf-connecting-ip": "192.0.2.42" });
  if (body !== undefined) headers.set("content-type", "application/json");
  if (token) headers.set("authorization", `Bearer ${token}`);
  if (origin) headers.set("origin", origin);
  const response = await app.fetch(
    new Request(`${env.APP_URL}${path}`, {
      method,
      headers,
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    }),
    env,
    ctx,
  );
  const text = await response.text();
  let data: any;
  try {
    data = JSON.parse(text);
  } catch {
    data = text;
  }
  return { response, data };
}
async function create() {
  const result = await request("/api/scans", "POST", {});
  expect(result.response.status).toBe(201);
  return result.data as {
    id: string;
    readToken: string;
    agentToken: string;
    ownerToken: string;
    expiresAt: string;
    agentExpiresAt: string;
    viewUrl: string;
    mcpUrl: string;
  };
}
const write = (revision: number) => ({
  revision,
  operationId: crypto.randomUUID(),
});
beforeEach(() => {
  db.exec("DELETE FROM agent_scan; DELETE FROM request_limit");
});
afterAll(async () => {
  await Promise.allSettled(pending);
  db.close();
});

describe("anonymous capability-scoped agent scans", () => {
  test("creation requires no account and discloses capabilities only once; state is private and encrypted", async () => {
    const scan = await create();
    expect(new URL(scan.viewUrl).search).toBe("");
    expect(new URL(scan.viewUrl).hash).toBe(`#key=${scan.readToken}`);
    expect(scan.mcpUrl).toBe(`${env.APP_URL}/mcp/scans/${scan.id}`);
    expect(
      new Set([scan.readToken, scan.ownerToken, scan.agentToken]).size,
    ).toBe(3);
    expect(Date.parse(scan.expiresAt) - Date.now()).toBeGreaterThan(
      29 * 86_400_000,
    );
    expect(Date.parse(scan.agentExpiresAt) - Date.now()).toBeLessThanOrEqual(
      7 * 86_400_000,
    );
    expect((await request(`/api/scans/${scan.id}`)).response.status).toBe(401);
    expect(
      (await request(`/api/scans/${scan.id}?key=${scan.readToken}`)).response
        .status,
    ).toBe(401);
    const state = await request(
      `/api/scans/${scan.id}`,
      "GET",
      undefined,
      scan.readToken,
    );
    expect(state.response.status).toBe(200);
    expect(state.response.headers.get("cache-control")).toBe("no-store");
    expect(state.response.headers.get("x-robots-tag")).toBe(
      "noindex, nofollow",
    );
    expect(state.data.evaluation.score).toBeNull();
    expect(state.data.evaluation.coverage).toBe(0);
    expect(state.data.target).toEqual({
      score: 85,
      coverage: 90,
      criticalGaps: 0,
      met: false,
    });
    expect(state.data.scan.status).toBe("waiting");
    expect(JSON.stringify(state.data)).not.toContain(scan.readToken);
    expect(JSON.stringify(state.data)).not.toContain(scan.agentToken);
    expect(JSON.stringify(state.data)).not.toContain(scan.ownerToken);
    const row = db
      .query("SELECT * FROM agent_scan WHERE id=?")
      .get(scan.id) as any;
    for (const token of [scan.readToken, scan.ownerToken, scan.agentToken])
      expect(JSON.stringify(row)).not.toContain(token);
    expect(row.payload).toStartWith("v1.");
    expect(row.payload).not.toContain("My security scan");
    expect(db.query("SELECT COUNT(*) AS n FROM user").get()).toEqual({ n: 0 });
  });

  test("reader and owner cannot mutate evidence; agent cannot rotate/delete; cross-scan tokens fail", async () => {
    const alice = await create(),
      bob = await create();
    for (const token of [alice.readToken, alice.ownerToken]) {
      expect(
        (await request(`/api/scans/${alice.id}/begin`, "POST", write(1), token))
          .response.status,
      ).toBe(403);
      expect(
        (await request(`/api/scans/${alice.id}`, "GET", undefined, token))
          .response.status,
      ).toBe(200);
    }
    expect(
      (await request(`/api/scans/${bob.id}`, "GET", undefined, alice.readToken))
        .response.status,
    ).toBe(401);
    expect(
      (
        await request(
          `/api/scans/${alice.id}/agent-token`,
          "POST",
          {},
          alice.agentToken,
        )
      ).response.status,
    ).toBe(403);
    expect(
      (
        await request(
          `/api/scans/${alice.id}`,
          "DELETE",
          { confirmation: "DELETE" },
          alice.agentToken,
        )
      ).response.status,
    ).toBe(403);
    expect(
      (
        await request(
          `/api/scans/${alice.id}`,
          "GET",
          undefined,
          alice.readToken,
          "https://evil.example",
        )
      ).response.status,
    ).toBe(403);
    expect(
      (
        await request(
          "/api/scans",
          "POST",
          {},
          undefined,
          "https://evil.example",
        )
      ).response.status,
    ).toBe(403);
    expect(
      (
        await request(
          `/mcp/scans/${alice.id}`,
          "GET",
          undefined,
          alice.agentToken,
        )
      ).response.status,
    ).toBe(405);
    expect((await request("/mcp/scans/not/a/route")).response.status).toBe(404);
    const page = await request(`/scan/${alice.id}`);
    expect(page.response.headers.get("cache-control")).toBe("no-store");
  });

  test("incremental evidence, actual deterministic scoring, context isolation, pause and re-audit lifecycle", async () => {
    const scan = await create(),
      base = `/api/scans/${scan.id}`;
    let result = await request(
      `${base}/begin`,
      "POST",
      write(1),
      scan.agentToken,
    );
    expect(result.response.status).toBe(200);
    expect(result.data.scan.run).toBe(1);
    result = await request(
      `${base}/assets`,
      "POST",
      {
        ...write(result.data.revision),
        kind: "email",
        label: "Primary email",
        value: "fixture@example.test",
        critical: true,
      },
      scan.agentToken,
    );
    expect(result.response.status).toBe(200);
    const assetId = result.data.workspace.assets[0].id;
    const check = CHECKS.find(
      (check) =>
        check.assetKinds?.includes("email") &&
        check.acceptedMethods.includes("guided"),
    )!;
    result = await request(
      `${base}/evidence`,
      "POST",
      {
        ...write(result.data.revision),
        checkId: check.id,
        assetId,
        status: "pass",
        notes:
          "The user confirmed the exact control in account security settings.",
        source: {
          kind: "user_confirmation",
          label: "Account security settings",
        },
      },
      scan.agentToken,
    );
    expect(result.response.status).toBe(200);
    const score = result.data.evaluation.score,
      coverage = result.data.evaluation.coverage;
    expect(coverage).toBeGreaterThan(0);
    const evaluated = evaluateWorkspace(
      result.data.workspace,
      result.data.evaluation.evaluatedAt,
    );
    expect(result.data.evaluation).toEqual(evaluated);
    expect(result.data.workspace.evidence[0].method).toBe("guided");
    expect(result.data.workspace.evidence[0].facts.source_kind).toBe(
      "user_confirmation",
    );
    result = await request(
      `${base}/actions`,
      "POST",
      {
        ...write(result.data.revision),
        checkId: check.id,
        assetId,
        status: "completed",
        notes: "Completed an authorized mitigation; verification is separate.",
      },
      scan.agentToken,
    );
    expect(result.data.evaluation.score).toBe(score);
    result = await request(
      `${base}/context`,
      "POST",
      {
        ...write(result.data.revision),
        title: "Synthetic report",
        description:
          "A public report is context only, with no personal match established.",
        url: "https://example.test/security/report",
        publishedAt: new Date().toISOString(),
      },
      scan.agentToken,
    );
    expect(result.response.status).toBe(200);
    expect(result.data.workspace.threatEvents[0].relevance).toBe("unassessed");
    expect(result.data.evaluation.score).toBe(score);
    expect(result.data.evaluation.coverage).toBe(coverage);
    result = await request(
      `${base}/progress`,
      "POST",
      {
        ...write(result.data.revision),
        status: "waiting_for_user",
        phase: "Confirm recovery",
        message: "Review the recovery contact in account settings to continue.",
      },
      scan.agentToken,
    );
    expect(result.data.scan.status).toBe("waiting_for_user");
    result = await request(
      `${base}/begin`,
      "POST",
      write(result.data.revision),
      scan.agentToken,
    );
    expect(result.data.scan.run).toBe(1);
    const completion = {
      ...write(result.data.revision),
      summary:
        "This pass assessed one control. The remaining checks still need verification.",
    };
    result = await request(
      `${base}/complete`,
      "POST",
      completion,
      scan.agentToken,
    );
    expect(result.data.scan.status).toBe("complete");
    expect(result.data.workspace.snapshots).toHaveLength(1);
    expect(result.data.target.met).toBe(false);
    const replay = await request(
      `${base}/complete`,
      "POST",
      completion,
      scan.agentToken,
    );
    expect(replay.data.revision).toBe(result.data.revision);
    expect(replay.data.workspace.snapshots).toHaveLength(1);
    expect(
      (
        await request(
          `${base}/progress`,
          "POST",
          {
            ...write(result.data.revision),
            status: "running",
            phase: "More checks",
            message: "Starting another check.",
          },
          scan.agentToken,
        )
      ).response.status,
    ).toBe(409);
    result = await request(
      `${base}/begin`,
      "POST",
      write(result.data.revision),
      scan.agentToken,
    );
    expect(result.data.scan.run).toBe(2);
    expect(result.data.workspace.evidence).toHaveLength(1);
    expect(result.data.workspace.snapshots).toHaveLength(1);
    expect(result.data.scan.completedAt).toBeUndefined();
    result = await request(
      `${base}/assets/${assetId}`,
      "PATCH",
      {
        ...write(result.data.revision),
        patch: { value: "changed@example.test" },
      },
      scan.agentToken,
    );
    expect(result.response.status).toBe(200);
    expect(result.data.workspace.evidence.length).toBeGreaterThan(1);
    expect(result.data.evaluation.coverage).toBeLessThan(coverage);
  });

  test("target requires coverage and zero critical gaps even when the score is high", async () => {
    const scan = await create();
    const row = db
      .query("SELECT payload FROM agent_scan WHERE id=?")
      .get(scan.id) as { payload: string };
    const data = await decrypt<any>(
      row.payload,
      env.DATA_ENCRYPTION_KEY,
      `scan:${scan.id}`,
    );
    let workspace = data.workspace;
    for (const kind of new Set(
      CHECKS.flatMap((check) => check.assetKinds ?? []),
    ))
      workspace = addAsset(workspace, {
        kind,
        label: `Synthetic ${kind}`,
        critical: false,
      });
    const observedAt = new Date(Date.now() - 1000).toISOString();
    for (const check of CHECKS) {
      const subjects = check.assetKinds
        ? workspace.assets
            .filter((asset: any) => check.assetKinds!.includes(asset.kind))
            .map((asset: any) => asset.id)
        : [undefined];
      for (const assetId of subjects)
        workspace = recordEvidence(workspace, {
          checkId: check.id,
          assetId,
          status: "pass",
          method: "guided",
          observedAt,
          notes: "Synthetic fixture verifies all specified control criteria.",
        });
    }
    const persist = async () =>
      db
        .query("UPDATE agent_scan SET payload=? WHERE id=?")
        .run(
          await encrypt(
            { ...data, workspace },
            env.DATA_ENCRYPTION_KEY,
            `scan:${scan.id}`,
          ),
          scan.id,
        );
    await persist();
    let state = await request(
      `/api/scans/${scan.id}`,
      "GET",
      undefined,
      scan.readToken,
    );
    expect(state.data.evaluation.score).toBe(100);
    expect(state.data.evaluation.coverage).toBe(100);
    expect(state.data.target.met).toBe(true);
    const check = CHECKS.find((check) => check.severity === "critical")!;
    const assetId = check.assetKinds
      ? workspace.assets.find((asset: any) =>
          check.assetKinds!.includes(asset.kind),
        ).id
      : undefined;
    workspace = recordEvidence(workspace, {
      checkId: check.id,
      assetId,
      status: "fail",
      method: "guided",
      notes:
        "Synthetic fixture confirms an unresolved critical protective gap.",
    });
    await persist();
    state = await request(
      `/api/scans/${scan.id}`,
      "GET",
      undefined,
      scan.readToken,
    );
    expect(state.data.evaluation.score).toBeGreaterThanOrEqual(85);
    expect(state.data.evaluation.coverage).toBe(100);
    expect(state.data.target.criticalGaps).toBeGreaterThan(0);
    expect(state.data.target.met).toBe(false);
  });

  test("CAS and operation IDs prevent lost updates and duplicate observations", async () => {
    const scan = await create(),
      base = `/api/scans/${scan.id}`;
    const start = { ...write(1) };
    const first = await request(
      `${base}/begin`,
      "POST",
      start,
      scan.agentToken,
    );
    expect(first.response.status).toBe(200);
    expect(
      (await request(`${base}/begin`, "POST", start, scan.agentToken)).data
        .revision,
    ).toBe(2);
    expect(
      (
        await request(
          `${base}/begin`,
          "POST",
          { ...start, revision: 2 },
          scan.agentToken,
        )
      ).data.error.code,
    ).toBe("OPERATION_CONFLICT");
    expect(
      (await request(`${base}/begin`, "POST", write(1), scan.agentToken)).data
        .error.code,
    ).toBe("REVISION_CONFLICT");
    const writes = await Promise.all(
      ["A", "B"].map((label) =>
        request(
          `${base}/assets`,
          "POST",
          { ...write(2), kind: "device", label, critical: false },
          scan.agentToken,
        ),
      ),
    );
    expect(writes.map((result) => result.response.status).sort()).toEqual([
      200, 409,
    ]);
    const final = await request(base, "GET", undefined, scan.readToken);
    expect(final.data.workspace.assets).toHaveLength(1);
    expect(final.data.revision).toBe(3);
  });

  test("capability rotation revokes old agent immediately, expiry denies access, owner deletion removes payload", async () => {
    const scan = await create(),
      base = `/api/scans/${scan.id}`;
    const rotated = await request(
      `${base}/agent-token`,
      "POST",
      {},
      scan.ownerToken,
    );
    expect(rotated.response.status).toBe(200);
    expect(rotated.data.agentToken).not.toBe(scan.agentToken);
    expect(
      (await request(base, "GET", undefined, scan.agentToken)).response.status,
    ).toBe(401);
    expect(
      (await request(base, "GET", undefined, rotated.data.agentToken)).response
        .status,
    ).toBe(200);
    db.query("UPDATE agent_scan SET agent_expires_at=? WHERE id=?").run(
      new Date(Date.now() - 1000).toISOString(),
      scan.id,
    );
    expect(
      (await request(base, "GET", undefined, rotated.data.agentToken)).response
        .status,
    ).toBe(401);
    expect(
      (await request(base, "GET", undefined, scan.readToken)).response.status,
    ).toBe(200);
    const deleted = await request(
      base,
      "DELETE",
      { confirmation: "DELETE" },
      scan.ownerToken,
    );
    expect(deleted.response.status).toBe(200);
    expect(deleted.data).toEqual({ deleted: true });
    expect(
      db.query("SELECT * FROM agent_scan WHERE id=?").get(scan.id),
    ).toBeNull();
    expect(
      (await request(base, "GET", undefined, scan.readToken)).response.status,
    ).toBe(401);
    const expired = await create();
    db.query("UPDATE agent_scan SET expires_at=? WHERE id=?").run(
      new Date(Date.now() - 1000).toISOString(),
      expired.id,
    );
    expect(
      (
        await request(
          `/api/scans/${expired.id}`,
          "GET",
          undefined,
          expired.ownerToken,
        )
      ).response.status,
    ).toBe(401);
    await worker.scheduled({} as ScheduledController, env, ctx);
    await Promise.allSettled(pending);
    expect(
      db.query("SELECT * FROM agent_scan WHERE id=?").get(expired.id),
    ).toBeNull();
  });

  test("strict payload bounds, input provenance, secrets and creation rate limits", async () => {
    const scan = await create(),
      base = `/api/scans/${scan.id}`;
    const check = CHECKS.find(
      (check) => !check.assetKinds && check.acceptedMethods.includes("guided"),
    )!;
    const evidence = {
      ...write(1),
      checkId: check.id,
      status: "pass",
      notes: "An actual verification was recorded for this check.",
    };
    expect(
      (await request(`${base}/evidence`, "POST", evidence, scan.agentToken))
        .response.status,
    ).toBe(400);
    expect(
      (
        await request(
          `${base}/evidence`,
          "POST",
          {
            ...evidence,
            method: "local",
            source: {
              kind: "local_observation",
              label: "Read-only local inspection",
            },
          },
          scan.agentToken,
        )
      ).response.status,
    ).toBe(400);
    expect(
      (
        await request(
          `${base}/progress`,
          "POST",
          {
            ...write(1),
            status: "running",
            phase: "Check",
            message: scan.agentToken,
          },
          scan.agentToken,
        )
      ).response.status,
    ).toBe(400);
    expect(
      (
        await request(
          `${base}/context`,
          "POST",
          {
            ...write(1),
            title: "Unsafe URL",
            description: "A source URL must not contain user credentials.",
            url: "https://user:password@example.test",
            publishedAt: new Date().toISOString(),
          },
          scan.agentToken,
        )
      ).response.status,
    ).toBe(400);
    expect(
      (
        await request(
          `${base}/evidence`,
          "POST",
          {
            ...evidence,
            notes: "password: unsafe-example-value",
            source: { kind: "user_confirmation", label: "Settings" },
          },
          scan.agentToken,
        )
      ).response.status,
    ).toBe(400);
    const bytes = new TextEncoder().encode(
      JSON.stringify({ body: "x".repeat(40_000) }),
    );
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(bytes.slice(0, 20_000));
        controller.enqueue(bytes.slice(20_000));
        controller.close();
      },
    });
    const bounded = await app.fetch(
      new Request(`${env.APP_URL}${base}/evidence`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${scan.agentToken}`,
          "content-type": "application/json",
        },
        body: stream,
      }),
      env,
      ctx,
    );
    expect(bounded.status).toBe(413);
    for (let i = 0; i < 4; i++) await create();
    expect((await request("/api/scans", "POST", {})).response.status).toBe(429);
    const row = db
      .query("SELECT payload FROM agent_scan WHERE id=?")
      .get(scan.id) as { payload: string };
    const payload = await decrypt<any>(
      row.payload,
      env.DATA_ENCRYPTION_KEY,
      `scan:${scan.id}`,
    );
    expect(payload.workspace.evidence).toHaveLength(0);
  });

  test("real HTTP MCP initializes, discovers scoped tools and incrementally records progress", async () => {
    const scan = await create();
    const hostedFetch = ((input: RequestInfo | URL, init?: RequestInit) =>
      app.fetch(new Request(input, init), env, ctx)) as typeof fetch;
    const connect = async (token: string) => {
      const client = new Client({
        name: "scan-integration-test",
        version: "1.0.0",
      });
      await client.connect(
        new StreamableHTTPClientTransport(new URL(scan.mcpUrl), {
          fetch: hostedFetch,
          requestInit: { headers: { Authorization: `Bearer ${token}` } },
        }),
      );
      return client;
    };
    const agent = await connect(scan.agentToken),
      reader = await connect(scan.readToken),
      owner = await connect(scan.ownerToken);
    try {
      expect((await reader.listTools()).tools.map((tool) => tool.name)).toEqual(
        ["get_scan", "get_catalog"],
      );
      expect((await owner.listTools()).tools.map((tool) => tool.name)).toEqual([
        "get_scan",
        "get_catalog",
      ]);
      expect((await agent.listTools()).tools).toHaveLength(10);
      const catalog = await agent.callTool({
        name: "get_catalog",
        arguments: {},
      });
      expect((catalog.structuredContent as any).checks).toHaveLength(38);
      const started = await agent.callTool({
        name: "begin_scan",
        arguments: write(1),
      });
      expect(started.isError).not.toBe(true);
      expect((started.structuredContent as any).scan.status).toBe("running");
      const blocked = await agent.callTool({
        name: "report_progress",
        arguments: {
          ...write(2),
          status: "blocked",
          phase: "Local settings unavailable",
          message:
            "The device does not expose its firewall status to this agent.",
        },
      });
      expect(blocked.isError).not.toBe(true);
      const observed = await reader.callTool({
        name: "get_scan",
        arguments: {},
      });
      expect((observed.structuredContent as any).scan.status).toBe("blocked");
      expect((observed.structuredContent as any).revision).toBe(3);
      const conflict = await agent.callTool({
        name: "begin_scan",
        arguments: write(1),
      });
      expect(conflict.isError).toBe(true);
      expect(JSON.stringify(conflict.content)).toContain("REVISION_CONFLICT");
    } finally {
      await Promise.all([agent.close(), reader.close(), owner.close()]);
    }
  });
});
