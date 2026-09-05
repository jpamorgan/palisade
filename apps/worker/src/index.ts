import { Hono } from "hono";
import { ZodError } from "zod";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { createPalisadeMcpServer } from "@palisade/mcp";
import {
  CATEGORIES,
  CHECKS,
  CATALOG_VERSION,
  SCORE_VERSION,
} from "@palisade/core";
import { createAuth } from "./auth";
import { authenticate, validateOrigin } from "./security";
import { createService, monitorWorkspace } from "./service";
import { rateLimit } from "./store";
import { openApi } from "./openapi";
import { idempotent } from "./idempotency";
import { AppError, type Env } from "./env";

const app = new Hono<{ Bindings: Env }>();
app.use("*", async (c, next) => {
  c.header("X-Content-Type-Options", "nosniff");
  c.header("Referrer-Policy", "no-referrer");
  c.header("X-Frame-Options", "DENY");
  c.header("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  c.header(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
  );
  if (c.req.url.startsWith("https:"))
    c.header(
      "Strict-Transport-Security",
      "max-age=31536000; includeSubDomains",
    );
  if (c.req.path.startsWith("/api") || c.req.path === "/mcp") {
    c.header("Cache-Control", "no-store");
    c.header("X-Robots-Tag", "noindex, nofollow");
  }
  await next();
});
app.onError((error, c) => {
  if (error instanceof AppError)
    return c.json(
      { error: { code: error.code, message: error.message } },
      error.status as 400,
    );
  if (error instanceof ZodError)
    return c.json(
      {
        error: {
          code: "INVALID_INPUT",
          message: error.issues
            .map((i) => `${i.path.join(".") || "input"}: ${i.message}`)
            .join("; ")
            .slice(0, 500),
        },
      },
      400,
    );
  // Do not log raw exceptions; provider payloads, identifiers, and credentials may be present.
  console.error(
    JSON.stringify({
      event: "request_failed",
      path: c.req.path.replace(/\/[a-f0-9-]{20,}/g, "/:id"),
      errorType: error.name,
    }),
  );
  return c.json(
    {
      error: {
        code: "INTERNAL_ERROR",
        message: "The request could not be completed. Please retry.",
      },
    },
    500,
  );
});
app.get("/api/health", (c) =>
  c.json({
    ok: true,
    service: "palisade",
    version: "0.1.0",
    catalogVersion: CATALOG_VERSION,
  }),
);
app.get("/openapi.json", (c) => c.json(openApi(c.env.APP_URL)));
app.get("/api/v1/catalog", (c) =>
  c.json({
    categories: CATEGORIES,
    checks: CHECKS,
    catalogVersion: CATALOG_VERSION,
    scoreVersion: SCORE_VERSION,
  }),
);
app.get("/robots.txt", (c) => c.text("User-agent: *\nDisallow: /\n"));
app.get("/.well-known/mcp/server-card.json", (c) =>
  c.json({
    name: "Palisade",
    description:
      "Private personal security audits, evidence and remediation. Create a scoped bearer token in Settings; configure it in your MCP client's Authorization header.",
    version: "0.1.0",
    transport: { type: "streamable-http", url: `${c.env.APP_URL}/mcp` },
    authentication: {
      type: "bearer",
      instructions:
        "https://github.com/jpamorgan/palisade/blob/main/packages/mcp/README.md",
    },
  }),
);
app.all("/api/auth/*", async (c) => {
  const request = c.req.raw;
  if (!request.body) return createAuth(c.env).handler(request);
  const bytes = await readLimitedBody(request, 32_768);
  return createAuth(c.env).handler(new Request(request, { body: bytes }));
});
async function readLimitedBody(request: Request, maximum: number) {
  if (!request.body) return new Uint8Array();
  if (Number(request.headers.get("content-length") ?? 0) > maximum)
    throw new AppError(
      "PAYLOAD_TOO_LARGE",
      "The request body is too large.",
      413,
    );
  const reader = request.body.getReader();
  let length = 0;
  const chunks: Uint8Array[] = [];
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.length;
    if (length > maximum) {
      await reader.cancel();
      throw new AppError(
        "PAYLOAD_TOO_LARGE",
        "The request body is too large.",
        413,
      );
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return bytes;
}
async function readBody(request: Request) {
  if (!request.body) return {};
  if (!request.headers.get("content-type")?.includes("application/json"))
    throw new AppError(
      "CONTENT_TYPE",
      "Use application/json for this request.",
      415,
    );
  const bytes = await readLimitedBody(request, 1_100_000);
  if (!bytes.length) return {};
  try {
    return JSON.parse(new TextDecoder().decode(bytes)) as unknown;
  } catch {
    throw new AppError("INVALID_JSON", "The request body is not valid JSON.");
  }
}
app.all("/api/v1/*", async (c) => {
  validateOrigin(c.req.raw, c.env);
  const principal = await authenticate(c.req.raw, c.env);
  await rateLimit(c.env, `api:${principal.id}`, 180, 60);
  const method = c.req.method as "GET" | "POST" | "PATCH" | "DELETE";
  if (!["GET", "POST", "PATCH", "DELETE"].includes(method))
    return c.json(
      { error: { code: "METHOD_NOT_ALLOWED", message: "Unsupported method." } },
      405,
    );
  const body = method === "GET" ? undefined : await readBody(c.req.raw);
  const path = c.req.path.slice("/api/v1".length);
  const run = () => createService(c.env, principal).request(method, path, body);
  const result =
    method === "GET"
      ? await run()
      : await idempotent(
          c.env,
          principal.id,
          c.req.header("Idempotency-Key"),
          method,
          path,
          body,
          run,
        );
  if (c.req.path === "/api/v1/export")
    c.header(
      "Content-Disposition",
      'attachment; filename="palisade-audit.json"',
    );
  return c.json(result as object);
});
app.all("/mcp", async (c) => {
  validateOrigin(c.req.raw, c.env);
  // Only explicit agent tokens on the machine endpoint; cookies never confer MCP authority.
  if (!c.req.header("authorization"))
    throw new AppError(
      "UNAUTHORIZED",
      "Configure an API token from Palisade Settings as a Bearer Authorization header.",
      401,
    );
  const principal = await authenticate(c.req.raw, c.env);
  await rateLimit(c.env, `mcp:${principal.id}`, 120, 60);
  if (c.req.method !== "POST")
    return new Response(null, { status: 405, headers: { Allow: "POST" } });
  const body = await readBody(c.req.raw);
  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });
  const server = createPalisadeMcpServer(createService(c.env, principal), {
    scopes: principal.scopes,
  });
  await server.connect(transport);
  const response = await transport.handleRequest(c.req.raw, {
    parsedBody: body,
  });
  c.executionCtx.waitUntil(server.close());
  return response;
});
app.all("*", async (c) => {
  if (c.req.path.startsWith("/api/"))
    return c.json(
      { error: { code: "NOT_FOUND", message: "API endpoint not found." } },
      404,
    );
  const response = await c.env.ASSETS.fetch(c.req.raw);
  return response;
});

export { app };
export default {
  fetch: app.fetch,
  async scheduled(
    _event: ScheduledController,
    env: Env,
    ctx: ExecutionContext,
  ) {
    const run = async () => {
      let cursor = "";
      while (true) {
        const { results } = await env.DB.prepare(
          "SELECT owner_id FROM workspace WHERE monitoring=1 AND owner_id>? ORDER BY owner_id LIMIT 100",
        )
          .bind(cursor)
          .all<{ owner_id: string }>();
        if (!results.length) break;
        if (env.MONITOR_QUEUE)
          await env.MONITOR_QUEUE.sendBatch(
            results.map((r) => ({ body: { userId: r.owner_id } })),
          );
        else
          for (const row of results) await monitorWorkspace(env, row.owner_id);
        cursor = results[results.length - 1]!.owner_id;
      }
      await env.DB.batch([
        env.DB.prepare("DELETE FROM request_limit WHERE window<?").bind(
          Math.floor(Date.now() / 1000) - 172800,
        ),
        env.DB.prepare("DELETE FROM operation WHERE created_at<?").bind(
          new Date(Date.now() - 86400000).toISOString(),
        ),
      ]);
    };
    ctx.waitUntil(run());
  },
  async queue(batch: MessageBatch<{ userId: string }>, env: Env) {
    for (const message of batch.messages) {
      try {
        await monitorWorkspace(env, message.body.userId);
        message.ack();
      } catch {
        message.retry({ delaySeconds: 120 });
      }
    }
  },
} satisfies ExportedHandler<Env, { userId: string }>;
