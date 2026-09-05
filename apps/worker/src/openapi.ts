import { z } from "zod";
import { EvaluationSchema, WorkspaceSchema } from "@palisade/core";
import { ApiBodies } from "./contracts";

type Operation = {
  path: string;
  method: "get" | "post" | "patch" | "delete";
  summary: string;
  body?: keyof typeof ApiBodies;
  result?:
    | "WorkspaceResult"
    | "Workspace"
    | "TokenResult"
    | "AssistantResult"
    | "Success";
  session?: boolean;
  public?: boolean;
};
const operations: Operation[] = [
  {
    path: "/catalog",
    method: "get",
    summary: "Read the versioned check catalog",
    public: true,
  },
  {
    path: "/workspace",
    method: "get",
    summary: "Read your workspace and current evaluation",
    result: "WorkspaceResult",
  },
  {
    path: "/workspace",
    method: "patch",
    summary: "Update preferences with optimistic revision checking",
    body: "updateWorkspace",
    result: "WorkspaceResult",
  },
  {
    path: "/workspace",
    method: "delete",
    summary:
      "Delete all audit data, provider credentials and API tokens; requires a fresh web session",
    body: "delete",
    session: true,
    result: "Success",
  },
  {
    path: "/assets",
    method: "post",
    summary: "Add an asset to the audit scope",
    body: "addAsset",
    result: "WorkspaceResult",
  },
  {
    path: "/assets/{id}",
    method: "patch",
    summary: "Edit asset details; identifier changes reopen affected evidence",
    body: "updateAsset",
    result: "WorkspaceResult",
  },
  {
    path: "/assets/{id}",
    method: "delete",
    summary:
      "Remove an asset from active scope, preserving historical evidence",
    result: "WorkspaceResult",
  },
  {
    path: "/evidence",
    method: "post",
    summary:
      "Record guided evidence; provider and local provenance cannot be claimed by this endpoint",
    body: "recordEvidence",
    result: "WorkspaceResult",
  },
  {
    path: "/actions",
    method: "post",
    summary: "Track a mitigation; completion does not verify evidence",
    body: "recordAction",
    result: "WorkspaceResult",
  },
  {
    path: "/audits",
    method: "post",
    summary:
      "Re-evaluate current evidence and save a snapshot; does not run external or local collectors",
    body: "createAudit",
    result: "WorkspaceResult",
  },
  {
    path: "/audits/{id}",
    method: "delete",
    summary: "Remove one saved snapshot while preserving current evidence",
    body: "delete",
    result: "WorkspaceResult",
  },
  {
    path: "/imports",
    method: "post",
    summary:
      "Merge an export; imported observations require verification and imported snapshot claims are discarded",
    body: "importWorkspace",
    result: "WorkspaceResult",
  },
  {
    path: "/export",
    method: "get",
    summary: "Download the complete workspace as private JSON",
    result: "Workspace",
  },
  {
    path: "/integrations",
    method: "get",
    summary:
      "Read configuration availability; stored credentials are never returned",
  },
  ...["hibp", "brave"].flatMap((provider) => [
    {
      path: `/integrations/${provider}`,
      method: "post" as const,
      summary: `Connect ${provider}; requires a fresh web session`,
      body: "connectProvider" as const,
      session: true,
    },
    {
      path: `/integrations/${provider}`,
      method: "delete" as const,
      summary: `Disconnect ${provider}; requires a fresh web session`,
      session: true,
    },
  ]),
  {
    path: "/scans/hibp",
    method: "post",
    summary:
      "Disclose and check your verified login email with HIBP; requires scan scope and explicit consent",
    body: "scanAsset",
    result: "WorkspaceResult",
  },
  {
    path: "/scans/threats",
    method: "post",
    summary: "Refresh public CISA and HIBP threat context; requires scan scope",
    result: "WorkspaceResult",
  },
  {
    path: "/scans/footprint",
    method: "post",
    summary:
      "Disclose an owned identity, email or domain to Brave Search; requires scan scope and consent",
    body: "scanAsset",
    result: "WorkspaceResult",
  },
  {
    path: "/tokens",
    method: "get",
    summary: "List token metadata; requires a web session",
    session: true,
  },
  {
    path: "/tokens",
    method: "post",
    summary:
      "Create a scoped token shown only once; requires a fresh web session",
    body: "createToken",
    session: true,
    result: "TokenResult",
  },
  {
    path: "/tokens/{id}",
    method: "delete",
    summary: "Revoke a token; requires a fresh web session",
    session: true,
    result: "Success",
  },
  {
    path: "/activity",
    method: "get",
    summary: "Read recent audit activity without sensitive identifiers",
  },
  {
    path: "/assistant",
    method: "post",
    summary: "Ask the optional Workers AI guide; it cannot change state",
    body: "assistant",
    result: "AssistantResult",
  },
];
const ref = (name: string) => ({ $ref: `#/components/schemas/${name}` });
const convert = (schema: z.ZodType) => {
  const { $schema, ...json } = z.toJSONSchema(schema, {
    unrepresentable: "any",
    io: "input",
  });
  return json;
};

export function openApi(origin: string) {
  const schemas: Record<string, unknown> = Object.fromEntries(
    Object.entries(ApiBodies).map(([name, schema]) => [name, convert(schema)]),
  );
  schemas.Workspace = convert(WorkspaceSchema);
  schemas.Evaluation = convert(EvaluationSchema);
  schemas.importWorkspace = {
    type: "object",
    required: ["workspace"],
    additionalProperties: false,
    properties: { workspace: ref("Workspace") },
  };
  schemas.WorkspaceResult = {
    type: "object",
    required: ["workspace", "evaluation", "revision"],
    properties: {
      workspace: ref("Workspace"),
      evaluation: ref("Evaluation"),
      revision: { type: "integer", minimum: 1 },
      receipt: {
        type: "object",
        description:
          "Provider status and coverage limitations, when this was a scan",
        properties: { status: { type: "string" }, message: { type: "string" } },
      },
    },
  };
  schemas.TokenResult = {
    type: "object",
    required: ["token", "record"],
    properties: {
      token: {
        type: "string",
        pattern: "^pal_[A-Za-z0-9_-]{43}$",
        readOnly: true,
      },
      record: {
        type: "object",
        required: ["id", "name", "scopes", "expiresAt"],
        properties: {
          id: { type: "string" },
          name: { type: "string" },
          prefix: { type: "string" },
          scopes: { type: "array", items: { enum: ["read", "write", "scan"] } },
          createdAt: { type: "string", format: "date-time" },
          expiresAt: { type: "string", format: "date-time" },
        },
      },
    },
  };
  schemas.AssistantResult = {
    type: "object",
    required: ["answer", "provider"],
    properties: { answer: { type: "string" }, provider: { type: "string" } },
  };
  schemas.Success = {
    type: "object",
    required: ["ok"],
    properties: { ok: { const: true } },
  };
  schemas.Error = {
    type: "object",
    required: ["error"],
    properties: {
      error: {
        type: "object",
        required: ["code", "message"],
        properties: { code: { type: "string" }, message: { type: "string" } },
      },
    },
  };
  const paths: Record<string, Record<string, unknown>> = {};
  for (const op of operations) {
    const parameters: unknown[] = [];
    if (op.path.includes("{id}"))
      parameters.push({
        name: "id",
        in: "path",
        required: true,
        schema: { type: "string" },
      });
    if (op.method !== "get")
      parameters.push({
        name: "Idempotency-Key",
        in: "header",
        required: false,
        description:
          "8–100 safe characters; same key and input replay the result for24hours. Token secrets are never replayed.",
        schema: {
          type: "string",
          minLength: 8,
          maxLength: 100,
          pattern: "^[A-Za-z0-9._:-]+$",
        },
      });
    const responses: Record<string, unknown> = {
      "200": {
        description: "Operation completed",
        content: {
          "application/json": {
            schema: op.result ? ref(op.result) : { type: "object" },
          },
        },
      },
    };
    for (const [status, description] of Object.entries({
      400: "Invalid input",
      401: "Authentication required",
      403: "Scope, ownership, origin or session requirement not met",
      409: "Concurrent edit or idempotency conflict",
      413: "Request or workspace exceeds its size limit",
      429: "Rate limit exceeded",
      503: "Provider unavailable",
    }))
      responses[status] = {
        description,
        content: { "application/json": { schema: ref("Error") } },
      };
    paths[op.path] ??= {};
    paths[op.path]![op.method] = {
      operationId: `${op.method}_${op.path.replace(/[^a-z]/g, "_")}`,
      summary: op.summary,
      security: op.public
        ? []
        : op.session
          ? [{ sessionAuth: [] }]
          : [{ bearerAuth: [] }, { sessionAuth: [] }],
      ...(parameters.length ? { parameters } : {}),
      ...(op.body
        ? {
            requestBody: {
              required: op.body !== "createAudit",
              content: { "application/json": { schema: ref(op.body) } },
            },
          }
        : {}),
      responses,
    };
  }
  return {
    openapi: "3.1.0",
    info: {
      title: "Palisade API",
      version: "0.1.0",
      description:
        "Personal security audit state and guided remediation. JSON requests are bounded to1.1MB; a workspace can contain up to1MB. GET requires read, mutations write, and provider scans scan. Cookies require same-origin requests; management requires a recent web session. Tokens cannot escalate access. Evidence is evaluated by the shared versioned core, never by an LLM.",
    },
    servers: [{ url: `${origin}/api/v1` }],
    paths,
    components: {
      schemas,
      securitySchemes: {
        bearerAuth: { type: "http", scheme: "bearer", bearerFormat: "pal_…" },
        sessionAuth: {
          type: "apiKey",
          in: "cookie",
          name: origin.startsWith("https:")
            ? "__Secure-better-auth.session_token"
            : "better-auth.session_token",
        },
      },
    },
  };
}
