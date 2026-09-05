import { z } from "zod";
import { ScanInputs } from "./scan-contracts";

/** Adds the agent-first surface while retaining the existing /api/v1 contract. */
export function addScanOpenApi(
  paths: Record<string, Record<string, unknown>>,
  schemas: Record<string, unknown>,
  origin: string,
) {
  const ref = (name: string) => ({ $ref: `#/components/schemas/${name}` });
  for (const [name, schema] of Object.entries(ScanInputs)) {
    const { $schema, ...json } = z.toJSONSchema(schema, {
      unrepresentable: "any",
      io: "input",
    });
    schemas[`Scan_${name}`] = json;
  }
  schemas.ScanState = {
    type: "object",
    required: [
      "scan",
      "workspace",
      "evaluation",
      "revision",
      "activity",
      "target",
    ],
    properties: {
      scan: {
        type: "object",
        required: [
          "id",
          "status",
          "phase",
          "message",
          "run",
          "createdAt",
          "updatedAt",
          "expiresAt",
        ],
        properties: {
          id: { type: "string", format: "uuid" },
          status: {
            enum: [
              "waiting",
              "running",
              "waiting_for_user",
              "blocked",
              "complete",
            ],
          },
          phase: { type: "string" },
          message: { type: "string" },
          run: { type: "integer", minimum: 0 },
          ...Object.fromEntries(
            ["createdAt", "updatedAt", "expiresAt", "completedAt"].map(
              (name) => [name, { type: "string", format: "date-time" }],
            ),
          ),
        },
      },
      workspace: ref("Workspace"),
      evaluation: ref("Evaluation"),
      revision: { type: "integer", minimum: 1 },
      activity: {
        type: "array",
        maxItems: 80,
        items: {
          type: "object",
          properties: {
            id: { type: "string" },
            kind: { type: "string" },
            message: { type: "string" },
            at: { type: "string", format: "date-time" },
          },
        },
      },
      target: {
        type: "object",
        properties: {
          score: { const: 85 },
          coverage: { const: 90 },
          met: { type: "boolean" },
          criticalGaps: { type: "integer", minimum: 0 },
        },
      },
    },
  };
  schemas.ScanCreated = {
    type: "object",
    required: [
      "id",
      "readToken",
      "agentToken",
      "ownerToken",
      "expiresAt",
      "agentExpiresAt",
      "viewUrl",
      "mcpUrl",
    ],
    properties: Object.fromEntries(
      [
        "id",
        "readToken",
        "agentToken",
        "ownerToken",
        "expiresAt",
        "agentExpiresAt",
        "viewUrl",
        "mcpUrl",
      ].map((name) => [name, { type: "string", readOnly: true }]),
    ),
    description:
      "Capability secrets are returned once. Keep the owner token in the creating browser; give only the scoped agent token and private read link to the agent. Scan access expires after 30 days, agent access after 7 days. Tokens go only in Authorization headers, never URL queries.",
  };
  type Entry = {
    path: string;
    method: string;
    summary: string;
    input?: keyof typeof ScanInputs;
    result?: string;
    public?: boolean;
    status?: string;
    scope?: string;
  };
  const entries: Entry[] = [
    {
      path: "/api/scans",
      method: "post",
      summary: "Create an anonymous private scan and independent capabilities",
      input: "empty",
      result: "ScanCreated",
      public: true,
      status: "201",
    },
    {
      path: "/api/scans/{id}",
      method: "get",
      summary: "Read live scan state using a read, agent or owner capability",
      result: "ScanState",
    },
    {
      path: "/api/scans/{id}",
      method: "delete",
      summary: "Permanently delete this scan",
      input: "delete",
      scope: "owner",
    },
    {
      path: "/api/scans/{id}/agent-token",
      method: "post",
      summary:
        "Issue fresh agent access and immediately revoke the previous agent capability",
      input: "empty",
      scope: "owner",
    },
    {
      path: "/api/scans/{id}/begin",
      method: "post",
      summary: "Begin or resume a pass, retaining previous evidence",
      input: "begin",
      result: "ScanState",
      scope: "agent",
    },
    {
      path: "/api/scans/{id}/assets",
      method: "post",
      summary: "Add an authorized asset",
      input: "asset",
      result: "ScanState",
      scope: "agent",
    },
    {
      path: "/api/scans/{id}/assets/{assetId}",
      method: "patch",
      summary:
        "Correct asset details using the patch object; omit assetId from the HTTP body",
      result: "ScanState",
      scope: "agent",
    },
    ...(
      ["evidence", "actions", "progress", "context", "complete"] as const
    ).map((path) => ({
      path: `/api/scans/{id}/${path}`,
      method: "post",
      summary: `Record scan ${path}; actions and public context do not award score credit`,
      input: (path === "actions" ? "action" : path) as keyof typeof ScanInputs,
      result: "ScanState",
      scope: "agent",
    })),
  ];
  for (const entry of entries) {
    const parameters = ["id", "assetId"]
      .filter((name) => entry.path.includes(`{${name}}`))
      .map((name) => ({
        name,
        in: "path",
        required: true,
        schema: { type: "string" },
      }));
    const input = entry.path.endsWith("/{assetId}")
      ? ScanInputs.updateAsset.omit({ assetId: true })
      : undefined;
    paths[entry.path] ??= {};
    paths[entry.path]![entry.method] = {
      servers: [{ url: new URL(origin).origin }],
      summary: entry.summary,
      description:
        entry.scope === "agent"
          ? "Requires the agent capability. State mutations require revision and a new operationId UUID; retry identical arguments with the same operationId. A conflict requires rereading current state. Request bodies are limited to 32 KiB; scan payloads to 900 KB."
          : entry.scope === "owner"
            ? "Requires the owner capability and the documented request body. Do not send revision or operationId for this owner operation."
            : undefined,
      security: entry.public ? [] : [{ bearerAuth: [] }],
      parameters,
      ...(entry.input || input
        ? {
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: input
                    ? z.toJSONSchema(input, {
                        unrepresentable: "any",
                        io: "input",
                      })
                    : ref(`Scan_${entry.input}`),
                },
              },
            },
          }
        : {}),
      responses: {
        [entry.status ?? "200"]: {
          description: "Operation completed",
          content: {
            "application/json": {
              schema: entry.result ? ref(entry.result) : { type: "object" },
            },
          },
        },
        ...Object.fromEntries(
          [400, 401, 403, 409, 413, 429].map((status) => [
            String(status),
            {
              description: "Input, access, revision or request limit error",
              content: { "application/json": { schema: ref("Error") } },
            },
          ]),
        ),
      },
    };
  }
}
