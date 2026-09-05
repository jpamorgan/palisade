import { afterAll, beforeEach, describe, expect, test } from "bun:test";
import worker, { app } from "../apps/worker/src/index";
import { encrypt, decrypt } from "../apps/worker/src/crypto";
import { createWorkspace, CHECKS } from "@palisade/core";
import { testDatabase } from "./d1";
import type { Env } from "../apps/worker/src/env";
import { idempotent } from "../apps/worker/src/idempotency";
import { rateLimit } from "../apps/worker/src/store";
import { createHmac } from "node:crypto";

const { db, binding } = testDatabase();
const env: Env = {
  DB: binding,
  APP_URL: "http://localhost:8787",
  BETTER_AUTH_SECRET: "test-only-auth-secret-with-at-least-32-characters",
  DATA_ENCRYPTION_KEY: "test-only-encryption-secret-at-least-32-characters",
  ASSETS: { fetch: async () => new Response("app") } as unknown as Fetcher,
};
const pending: Promise<unknown>[] = [];
const ctx = {
  waitUntil: (p: Promise<unknown>) => pending.push(p),
  passThroughOnException() {},
} as unknown as ExecutionContext;
async function request(
  path: string,
  method = "GET",
  body?: unknown,
  cookie?: string,
  token?: string,
  origin = "http://localhost:8787",
) {
  const headers: Record<string, string> = { Origin: origin };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (cookie) headers.Cookie = cookie;
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await app.fetch(
    new Request(`http://localhost:8787${path}`, {
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
async function signup(email: string) {
  const result = await request("/api/auth/sign-up/email", "POST", {
    email,
    name: "Test User",
    password: "A-test-passphrase-123456!",
  });
  expect(result.response.status).toBe(200);
  const cookies = result.response.headers
    .getSetCookie()
    .map((c) => c.split(";")[0])
    .join("; ");
  expect(cookies).toContain("session_token");
  return { cookie: cookies, id: result.data.user.id };
}
afterAll(async () => {
  await Promise.allSettled(pending);
  db.close();
});
beforeEach(() => {
  db.exec("DELETE FROM rate_limit");
});

describe("hosted application contract", () => {
  test("public catalog is available; private state rejects anonymous requests", async () => {
    const catalog = await request("/api/v1/catalog");
    expect(catalog.response.status).toBe(200);
    expect(catalog.data.categories).toHaveLength(8);
    expect(catalog.data.checks.length).toBeGreaterThanOrEqual(32);
    expect((await request("/api/v1/workspace")).response.status).toBe(401);
  });
  test("signup, evidence, action, snapshot, export, token and tenant isolation", async () => {
    const alice = await signup("alice@example.test"),
      bob = await signup("bob@example.test");
    let state = await request(
      "/api/v1/workspace",
      "GET",
      undefined,
      alice.cookie,
    );
    expect(state.response.status).toBe(200);
    expect(state.data.evaluation.coverage).toBe(0);
    const originalId = state.data.workspace.id;
    state = await request(
      "/api/v1/assets",
      "POST",
      {
        kind: "email",
        label: "Primary email",
        value: "alice@example.test",
        critical: true,
      },
      alice.cookie,
    );
    expect(state.response.status).toBe(200);
    const assetId = state.data.workspace.assets[0].id;
    const check = CHECKS.find(
      (c) =>
        c.assetKinds?.includes("email") && c.acceptedMethods.includes("guided"),
    )!;
    state = await request(
      "/api/v1/evidence",
      "POST",
      {
        checkId: check.id,
        assetId,
        status: "pass",
        notes:
          "Reviewed the account security settings and confirmed this control is enabled.",
      },
      alice.cookie,
    );
    expect(state.response.status).toBe(200);
    expect(state.data.evaluation.coverage).toBeGreaterThan(0);
    const score = state.data.evaluation.score;
    state = await request(
      "/api/v1/actions",
      "POST",
      { checkId: check.id, assetId, status: "completed" },
      alice.cookie,
    );
    expect(state.response.status).toBe(200);
    expect(state.data.evaluation.score).toBe(score);
    state = await request("/api/v1/audits", "POST", {}, alice.cookie);
    expect(state.data.workspace.snapshots).toHaveLength(1);
    const saved = await request(
      "/api/v1/export",
      "GET",
      undefined,
      alice.cookie,
    );
    expect(saved.data.id).toBe(originalId);
    const token = await request(
      "/api/v1/tokens",
      "POST",
      { name: "Read-only test", scopes: ["read"] },
      alice.cookie,
    );
    expect(token.response.status).toBe(200);
    expect(token.data.token).toStartWith("pal_");
    const viaToken = await request(
      "/api/v1/workspace",
      "GET",
      undefined,
      undefined,
      token.data.token,
    );
    expect(viaToken.data.workspace.id).toBe(originalId);
    expect(
      (
        await request(
          "/api/v1/evidence",
          "POST",
          {},
          undefined,
          token.data.token,
        )
      ).response.status,
    ).toBe(403);
    expect(
      (
        await request(
          "/api/v1/tokens",
          "GET",
          undefined,
          undefined,
          token.data.token,
        )
      ).response.status,
    ).toBe(403);
    const bobState = await request(
      "/api/v1/workspace",
      "GET",
      undefined,
      bob.cookie,
    );
    expect(bobState.data.workspace.id).not.toBe(originalId);
    expect(bobState.data.workspace.evidence).toHaveLength(0);
    const stolenAsset = await request(
      `/api/v1/assets/${assetId}`,
      "DELETE",
      undefined,
      bob.cookie,
    );
    expect(stolenAsset.response.status).toBe(400);
    const raw = db
      .query("SELECT payload FROM workspace WHERE owner_id=?")
      .get(alice.id) as { payload: string };
    expect(raw.payload).toStartWith("v1.");
    expect(raw.payload).not.toContain("alice@example.test");
    const forged = await request(
      "/api/v1/evidence",
      "POST",
      {
        checkId: check.id,
        assetId,
        status: "pass",
        method: "provider",
        notes: "Trying to claim provider authority.",
      },
      alice.cookie,
    );
    expect(forged.response.status).toBe(400);
    const crossOrigin = await request(
      "/api/v1/assets",
      "POST",
      { kind: "email", label: "CSRF", critical: true },
      alice.cookie,
      undefined,
      "https://evil.example",
    );
    expect(crossOrigin.response.status).toBe(403);
    const conflict = await request(
      "/api/v1/workspace",
      "PATCH",
      { name: "Old revision", revision: 1 },
      alice.cookie,
    );
    expect(conflict.response.status).toBe(409);
    await request(
      `/api/v1/tokens/${token.data.record.id}`,
      "DELETE",
      undefined,
      alice.cookie,
    );
    expect(
      (
        await request(
          "/api/v1/workspace",
          "GET",
          undefined,
          undefined,
          token.data.token,
        )
      ).response.status,
    ).toBe(401);
    const token2 = await request(
      "/api/v1/tokens",
      "POST",
      { name: "Deletion test", scopes: ["read", "write"] },
      alice.cookie,
    );
    const deleted = await request(
      "/api/v1/workspace",
      "DELETE",
      { confirmation: "DELETE" },
      alice.cookie,
    );
    expect(deleted.response.status).toBe(200);
    expect(
      db.query("SELECT * FROM workspace WHERE owner_id=?").get(alice.id),
    ).toBeNull();
    expect(
      (
        await request(
          "/api/v1/workspace",
          "GET",
          undefined,
          undefined,
          token2.data.token,
        )
      ).response.status,
    ).toBe(401);
  });
  test("local imports cannot create authoritative evidence or steal tenant IDs", async () => {
    const user = await signup("importer@example.test"),
      external = createWorkspace("External");
    const result = await request(
      "/api/v1/imports",
      "POST",
      { workspace: external },
      user.cookie,
    );
    expect(result.response.status).toBe(200);
    expect(result.data.workspace.id).not.toBe(external.id);
    const malformed = await request(
      "/api/v1/imports",
      "POST",
      { workspace: { schemaVersion: 1, evil: true } },
      user.cookie,
    );
    expect(malformed.response.status).toBe(400);
    const badRegion = await request(
      "/api/v1/workspace",
      "PATCH",
      { settings: { region: "" }, revision: result.data.revision },
      user.cookie,
    );
    expect(badRegion.response.status).toBe(400);
  });
  test("encryption authenticates both tenant and ciphertext", async () => {
    const cipher = await encrypt(
      { sensitive: true },
      env.DATA_ENCRYPTION_KEY,
      "alice",
    );
    expect(
      await decrypt<{ sensitive: boolean }>(
        cipher,
        env.DATA_ENCRYPTION_KEY,
        "alice",
      ),
    ).toEqual({ sensitive: true });
    await expect(
      decrypt(cipher, env.DATA_ENCRYPTION_KEY, "bob"),
    ).rejects.toThrow();
  });
  test("asset edits reopen affected evidence and snapshots can be removed without losing current evidence", async () => {
    const user = await signup("editor@example.test");
    let state = await request(
      "/api/v1/assets",
      "POST",
      {
        kind: "email",
        label: "Original",
        value: "original@example.test",
        critical: true,
      },
      user.cookie,
    );
    const assetId = state.data.workspace.assets[0].id;
    const check = CHECKS.find(
      (c) =>
        c.assetKinds?.includes("email") && c.acceptedMethods.includes("guided"),
    )!;
    await request(
      "/api/v1/evidence",
      "POST",
      {
        checkId: check.id,
        assetId,
        status: "pass",
        notes: "Confirmed this protection in the original account settings.",
      },
      user.cookie,
    );
    state = await request("/api/v1/audits", "POST", {}, user.cookie);
    const snapshot = state.data.workspace.snapshots[0];
    state = await request(
      `/api/v1/assets/${assetId}`,
      "PATCH",
      { value: "replacement@example.test" },
      user.cookie,
    );
    expect(state.response.status).toBe(200);
    expect(state.data.workspace.evidence).toHaveLength(2);
    expect(
      state.data.evaluation.checks.find((r: any) => r.checkId === check.id)
        .status,
    ).toBe("unknown");
    expect(state.data.workspace.snapshots[0]).toEqual(snapshot);
    expect(
      (
        await request(
          `/api/v1/audits/${snapshot.id}`,
          "DELETE",
          {},
          user.cookie,
        )
      ).response.status,
    ).toBe(400);
    state = await request(
      `/api/v1/audits/${snapshot.id}`,
      "DELETE",
      { confirmation: "DELETE" },
      user.cookie,
    );
    expect(state.response.status).toBe(200);
    expect(state.data.workspace.snapshots).toHaveLength(0);
    expect(state.data.workspace.evidence).toHaveLength(2);
  });
  test("streamed authentication bodies are bounded and all rate-limit windows expire consistently", async () => {
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(
          new TextEncoder().encode(
            JSON.stringify({
              email: "stream@example.test",
              padding: "x".repeat(33_000),
            }),
          ),
        );
        controller.close();
      },
    });
    const response = await app.fetch(
      new Request(`${env.APP_URL}/api/auth/sign-up/email`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Origin: env.APP_URL },
        body: stream,
      }),
      env,
      ctx,
    );
    expect(response.status).toBe(413);
    await rateLimit(env, "test:minute", 2, 60);
    await rateLimit(env, "test:hour", 2, 3600);
    await rateLimit(env, "test:minute", 2, 60);
    await expect(rateLimit(env, "test:minute", 2, 60)).rejects.toThrow(
      "Too many requests",
    );
    db.exec("UPDATE request_limit SET window=1 WHERE key LIKE 'test:%'");
    const work: Promise<unknown>[] = [];
    await worker.scheduled({} as ScheduledController, env, {
      waitUntil: (p: Promise<unknown>) => work.push(p),
    } as unknown as ExecutionContext);
    await Promise.all(work);
    expect(
      db.query("SELECT * FROM request_limit WHERE key LIKE 'test:%'").all(),
    ).toHaveLength(0);
  });
  test("TOTP enrollment verifies possession and backup codes complete sign-in only once", async () => {
    const user = await signup("twofactor@example.test");
    const enrolled = await request(
      "/api/auth/two-factor/enable",
      "POST",
      { password: "A-test-passphrase-123456!" },
      user.cookie,
    );
    expect(enrolled.response.status).toBe(200);
    const uri = new URL(enrolled.data.totpURI),
      secret = uri.searchParams.get("secret")!;
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = "";
    for (const character of secret.replace(/=+$/, ""))
      bits += alphabet
        .indexOf(character.toUpperCase())
        .toString(2)
        .padStart(5, "0");
    const key = Buffer.from(
      Array.from({ length: Math.floor(bits.length / 8) }, (_, i) =>
        parseInt(bits.slice(i * 8, i * 8 + 8), 2),
      ),
    );
    const counter = Buffer.alloc(8);
    counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)));
    const mac = createHmac("sha1", key).update(counter).digest(),
      offset = mac[19]! & 15;
    const code = String(
      (new DataView(mac.buffer, mac.byteOffset, mac.byteLength).getUint32(
        offset,
      ) &
        0x7fffffff) %
        1_000_000,
    ).padStart(6, "0");
    const verified = await request(
      "/api/auth/two-factor/verify-totp",
      "POST",
      { code },
      user.cookie,
    );
    expect(verified.response.status).toBe(200);
    const stored = db
      .query("SELECT secret,backup_codes FROM two_factor WHERE user_id=?")
      .get(user.id) as { secret: string; backup_codes: string };
    expect(stored.secret).not.toContain(secret);
    expect(stored.backup_codes).not.toContain(enrolled.data.backupCodes[0]);
    const signin = await request("/api/auth/sign-in/email", "POST", {
      email: "twofactor@example.test",
      password: "A-test-passphrase-123456!",
    });
    expect(signin.response.status).toBe(200);
    expect(signin.data.twoFactorRedirect).toBe(true);
    const challenge = signin.response.headers
      .getSetCookie()
      .map((c) => c.split(";")[0])
      .join("; ");
    expect(
      (await request("/api/v1/workspace", "GET", undefined, challenge)).response
        .status,
    ).toBe(401);
    const recovered = await request(
      "/api/auth/two-factor/verify-backup-code",
      "POST",
      { code: enrolled.data.backupCodes[0] },
      challenge,
    );
    expect(recovered.response.status).toBe(200);
    const recoveredSession = recovered.response.headers
      .getSetCookie()
      .map((c) => c.split(";")[0])
      .join("; ");
    expect(
      (await request("/api/v1/workspace", "GET", undefined, recoveredSession))
        .response.status,
    ).toBe(200);
    const signinAgain = await request("/api/auth/sign-in/email", "POST", {
      email: "twofactor@example.test",
      password: "A-test-passphrase-123456!",
    });
    const challengeAgain = signinAgain.response.headers
      .getSetCookie()
      .map((c) => c.split(";")[0])
      .join("; ");
    const reused = await request(
      "/api/auth/two-factor/verify-backup-code",
      "POST",
      { code: enrolled.data.backupCodes[0] },
      challengeAgain,
    );
    expect(reused.response.status).toBeGreaterThanOrEqual(400);
  });
  test("idempotency replays writes without storing cleartext or creating duplicate tokens", async () => {
    const user = await signup("idempotent@example.test");
    let calls = 0;
    const run = async () => ({ count: ++calls });
    expect(
      await idempotent(
        env,
        user.id,
        "operation-0001",
        "POST",
        "/assets",
        { label: "private" },
        run,
      ),
    ).toEqual({ count: 1 });
    expect(
      await idempotent(
        env,
        user.id,
        "operation-0001",
        "POST",
        "/assets",
        { label: "private" },
        run,
      ),
    ).toEqual({ count: 1 });
    expect(calls).toBe(1);
    await expect(
      idempotent(
        env,
        user.id,
        "operation-0001",
        "POST",
        "/assets",
        { label: "different" },
        run,
      ),
    ).rejects.toThrow("different input");
    await idempotent(
      env,
      user.id,
      "token-operation",
      "POST",
      "/tokens",
      {},
      run,
    );
    await expect(
      idempotent(env, user.id, "token-operation", "POST", "/tokens", {}, run),
    ).rejects.toThrow("displayed once");
    expect(calls).toBe(2);
  });
  test("hosted MCP initializes and lists only tools granted by the token", async () => {
    const user = await signup("mcp@example.test");
    const token = await request(
      "/api/v1/tokens",
      "POST",
      { name: "MCP reader", scopes: ["read"] },
      user.cookie,
    );
    const rpc = async (body: unknown) => {
      const response = await app.fetch(
        new Request("http://localhost:8787/mcp", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token.data.token}`,
            "Content-Type": "application/json",
            Accept: "application/json, text/event-stream",
          },
          body: JSON.stringify(body),
        }),
        env,
        ctx,
      );
      return { status: response.status, data: (await response.json()) as any };
    };
    const init = await rpc({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "Palisade integration test", version: "1" },
      },
    });
    expect(init.status).toBe(200);
    expect(init.data.result.serverInfo.name).toContain("palisade");
    const list = await rpc({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
      params: {},
    });
    expect(list.status).toBe(200);
    expect(list.data.result.tools.map((t: any) => t.name)).toContain(
      "get_workspace",
    );
    expect(list.data.result.tools.map((t: any) => t.name)).not.toContain(
      "record_evidence",
    );
    const call = await rpc({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "get_workspace", arguments: {} },
    });
    expect(call.data.result.isError).not.toBe(true);
    expect(call.data.result.content[0].text).toContain("coverage");
    expect(
      (await request("/mcp", "POST", {}, user.cookie)).response.status,
    ).toBe(401);
  });
  test("account deletion rejects a wrong password and cascades only that user's private data", async () => {
    const user = await signup("deleteaccount@example.test");
    await request("/api/v1/workspace", "GET", undefined, user.cookie);
    const token = await request(
      "/api/v1/tokens",
      "POST",
      { name: "Cleanup test", scopes: ["read"] },
      user.cookie,
    );
    const refused = await request(
      "/api/auth/delete-user",
      "POST",
      { password: "wrong-password-for-this-test" },
      user.cookie,
    );
    expect(refused.response.status).toBeGreaterThanOrEqual(400);
    expect(
      (
        await request(
          "/api/v1/workspace",
          "GET",
          undefined,
          undefined,
          token.data.token,
        )
      ).response.status,
    ).toBe(200);
    const deleted = await request(
      "/api/auth/delete-user",
      "POST",
      { password: "A-test-passphrase-123456!" },
      user.cookie,
    );
    expect(deleted.response.status).toBe(200);
    for (const table of ["workspace", "api_token", "activity", "integration"])
      expect(
        db.query(`SELECT * FROM ${table} WHERE owner_id=?`).all(user.id),
      ).toHaveLength(0);
    expect(db.query("SELECT * FROM user WHERE id=?").get(user.id)).toBeNull();
    expect(
      (
        await request(
          "/api/v1/workspace",
          "GET",
          undefined,
          undefined,
          token.data.token,
        )
      ).response.status,
    ).toBe(401);
  });
  test("scheduled monitoring queues only opted-in users and refreshes context without consuming history", async () => {
    const user = await signup("monitor@example.test");
    const initial = await request(
      "/api/v1/workspace",
      "GET",
      undefined,
      user.cookie,
    );
    await request(
      "/api/v1/workspace",
      "PATCH",
      { settings: { monitoring: true }, revision: initial.data.revision },
      user.cookie,
    );
    const queued: { body: { userId: string } }[] = [];
    const monitoringEnv = {
      ...env,
      MONITOR_QUEUE: {
        sendBatch: async (messages: { body: { userId: string } }[]) => {
          queued.push(...messages);
        },
      },
    } as unknown as Env;
    const work: Promise<unknown>[] = [];
    await worker.scheduled({} as ScheduledController, monitoringEnv, {
      waitUntil: (p: Promise<unknown>) => work.push(p),
    } as unknown as ExecutionContext);
    await Promise.all(work);
    expect(queued.map((message) => message.body.userId)).toEqual([user.id]);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL) =>
      String(input).includes("cisa.gov")
        ? Response.json({
            vulnerabilities: [
              {
                cveID: "CVE-2026-99999",
                vendorProject: "Synthetic",
                product: "Fixture",
                vulnerabilityName: "Synthetic security fixture",
                dateAdded: "2026-01-01",
                shortDescription: "Test-only public vulnerability",
                requiredAction: "Apply the synthetic fixture update.",
              },
            ],
          })
        : Response.json([])) as typeof fetch;
    let acknowledgements = 0,
      retries = 0;
    try {
      await worker.queue(
        {
          messages: [
            {
              body: { userId: user.id },
              ack() {
                acknowledgements++;
              },
              retry() {
                retries++;
              },
            },
          ],
        } as unknown as MessageBatch<{ userId: string }>,
        env,
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
    expect(acknowledgements).toBe(1);
    expect(retries).toBe(0);
    const after = await request(
      "/api/v1/workspace",
      "GET",
      undefined,
      user.cookie,
    );
    expect(after.data.workspace.threatEvents).toHaveLength(1);
    expect(after.data.workspace.threatEvents[0].relevance).toBe("unassessed");
    expect(after.data.workspace.snapshots).toHaveLength(0);
    expect(after.data.evaluation.score).toBeNull();
    await request(
      "/api/v1/workspace",
      "PATCH",
      { settings: { monitoring: false }, revision: after.data.revision },
      user.cookie,
    );
  });
});
