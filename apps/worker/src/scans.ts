import { z } from "zod";
import {
  CATEGORIES,
  CHECKS,
  CATALOG_VERSION,
  SCORE_VERSION,
  WorkspaceSchema,
  createWorkspace,
  evaluateWorkspace,
  addAsset,
  updateAsset,
  recordEvidence,
  recordAction,
  createSnapshot,
  type Workspace,
} from "@palisade/core";
import { decrypt, encrypt, hashToken, randomToken } from "./crypto";
import { AppError, type Env } from "./env";
import { rateLimit } from "./store";
import { ScanInputs } from "./scan-contracts";

export type ScanRole = "read" | "agent" | "owner";
export interface ScanPrincipal {
  id: string;
  role: ScanRole;
  hash: string;
}
const Day = 86_400_000;
const ActivitySchema = z
  .object({
    id: z.uuid(),
    kind: z.string().max(80),
    message: z.string().max(600),
    at: z.iso.datetime(),
  })
  .strict();
const ScanPayloadSchema = z
  .object({
    workspace: WorkspaceSchema,
    status: z.enum([
      "waiting",
      "running",
      "waiting_for_user",
      "blocked",
      "complete",
    ]),
    phase: z.string().max(80),
    message: z.string().max(600),
    completedAt: z.iso.datetime().optional(),
    run: z.number().int().nonnegative(),
    activity: z.array(ActivitySchema).max(80),
    operations: z
      .array(
        z.object({ id: z.uuid(), fingerprint: z.string().length(64) }).strict(),
      )
      .max(100),
  })
  .strict();
type ScanPayload = Omit<z.infer<typeof ScanPayloadSchema>, "workspace"> & {
  workspace: Workspace;
};
interface ScanRow {
  id: string;
  payload: string;
  revision: number;
  read_hash: string;
  owner_hash: string;
  agent_hash: string;
  agent_expires_at: string;
  created_at: string;
  expires_at: string;
}
const timestamp = () => new Date().toISOString();
const privateError = () =>
  new AppError(
    "SCAN_UNAVAILABLE",
    "This scan link is invalid, expired, or has been deleted.",
    401,
  );
function publicState(row: ScanRow, data: ScanPayload) {
  const evaluation = evaluateWorkspace(data.workspace);
  const criticalGaps = evaluation.findings.filter(
    (finding) => finding.severity === "critical",
  ).length;
  return {
    scan: {
      id: row.id,
      status: data.status,
      phase: data.phase,
      message: data.message,
      createdAt: row.created_at,
      updatedAt: data.workspace.updatedAt,
      expiresAt: row.expires_at,
      ...(data.completedAt ? { completedAt: data.completedAt } : {}),
      run: data.run,
    },
    workspace: data.workspace,
    evaluation,
    revision: row.revision,
    activity: data.activity,
    target: {
      score: 85,
      coverage: 90,
      criticalGaps,
      met:
        evaluation.score !== null &&
        evaluation.score >= 85 &&
        evaluation.coverage >= 90 &&
        criticalGaps === 0,
    },
  };
}

export function validateScanOrigin(request: Request, env: Env) {
  const origin = request.headers.get("origin");
  const allowed = [new URL(env.APP_URL).origin];
  if (allowed[0] === "http://localhost:8787")
    allowed.push("http://localhost:5173", "http://localhost:3000");
  if (
    (origin && !allowed.includes(origin)) ||
    request.headers.get("sec-fetch-site") === "cross-site"
  )
    throw new AppError(
      "ORIGIN_REJECTED",
      "This request came from an untrusted origin.",
      403,
    );
}
export async function createScan(env: Env, request: Request) {
  validateScanOrigin(request, env);
  // Cloudflare supplies this header. Hash it before persistence and never record raw IPs.
  const ipHash = await hashToken(
    request.headers.get("cf-connecting-ip") ?? "local",
  );
  await rateLimit(env, `scan-create:${ipHash}`, 5, 3600);
  await rateLimit(env, "scan-create:global", 1000, 86400);
  const id = crypto.randomUUID();
  const readToken = randomToken(),
    ownerToken = randomToken(),
    agentToken = randomToken();
  const now = timestamp(),
    expiresAt = new Date(Date.now() + 30 * Day).toISOString();
  const agentExpiresAt = new Date(Date.now() + 7 * Day).toISOString();
  const data: ScanPayload = {
    workspace: createWorkspace("My security scan"),
    status: "waiting",
    phase: "Ready for your agent",
    message: "Paste the prompt into your agent to begin.",
    run: 0,
    activity: [],
    operations: [],
  };
  const payload = await encrypt(data, env.DATA_ENCRYPTION_KEY, `scan:${id}`);
  const hashes = await Promise.all([
    hashToken(readToken),
    hashToken(ownerToken),
    hashToken(agentToken),
  ]);
  await env.DB.prepare(
    "INSERT INTO agent_scan(id,payload,revision,read_hash,owner_hash,agent_hash,agent_expires_at,created_at,expires_at) VALUES(?,?,1,?,?,?,?,?,?)",
  )
    .bind(id, payload, ...hashes, agentExpiresAt, now, expiresAt)
    .run();
  const origin = new URL(env.APP_URL).origin;
  return {
    id,
    readToken,
    agentToken,
    ownerToken,
    expiresAt,
    agentExpiresAt,
    viewUrl: `${origin}/scan/${id}#key=${readToken}`,
    mcpUrl: `${origin}/mcp/scans/${id}`,
  };
}
export async function authenticateScan(
  request: Request,
  env: Env,
  id: string,
): Promise<ScanPrincipal> {
  const authorization = request.headers.get("authorization");
  if (
    !z.uuid().safeParse(id).success ||
    !authorization ||
    !/^Bearer pal_[a-zA-Z0-9_-]{43}$/.test(authorization)
  )
    throw privateError();
  const hash = await hashToken(authorization.slice(7));
  const row = await env.DB.prepare(
    "SELECT read_hash,owner_hash,agent_hash,agent_expires_at,expires_at FROM agent_scan WHERE id=?",
  )
    .bind(id)
    .first<
      Pick<
        ScanRow,
        | "read_hash"
        | "owner_hash"
        | "agent_hash"
        | "agent_expires_at"
        | "expires_at"
      >
    >();
  if (!row || row.expires_at <= timestamp()) throw privateError();
  const role =
    hash === row.read_hash
      ? "read"
      : hash === row.owner_hash
        ? "owner"
        : hash === row.agent_hash && row.agent_expires_at > timestamp()
          ? "agent"
          : undefined;
  if (!role) throw privateError();
  await rateLimit(env, `scan:${id}:${role}`, role === "read" ? 120 : 180, 60);
  return { id, role, hash };
}
async function loadScan(env: Env, principal: ScanPrincipal) {
  const row = await env.DB.prepare("SELECT * FROM agent_scan WHERE id=?")
    .bind(principal.id)
    .first<ScanRow>();
  if (!row || row.expires_at <= timestamp()) throw privateError();
  // Recheck capability during every operation to close rotation/deletion races.
  if (
    row[`${principal.role}_hash`] !== principal.hash ||
    (principal.role === "agent" && row.agent_expires_at <= timestamp())
  )
    throw privateError();
  const data = ScanPayloadSchema.parse(
    await decrypt(row.payload, env.DATA_ENCRYPTION_KEY, `scan:${row.id}`),
  );
  return { row, data };
}
export async function readScan(env: Env, principal: ScanPrincipal) {
  const { row, data } = await loadScan(env, principal);
  return publicState(row, data);
}
function requireRole(principal: ScanPrincipal, role: ScanRole) {
  if (principal.role !== role)
    throw new AppError(
      "FORBIDDEN",
      `This action requires the ${role} capability.`,
      403,
    );
}
export async function rotateScanAgent(env: Env, principal: ScanPrincipal) {
  requireRole(principal, "owner");
  const { row } = await loadScan(env, principal);
  const agentToken = randomToken(),
    agentExpiresAt = new Date(
      Math.min(Date.now() + 7 * Day, Date.parse(row.expires_at)),
    ).toISOString();
  const result = await env.DB.prepare(
    "UPDATE agent_scan SET agent_hash=?,agent_expires_at=? WHERE id=? AND owner_hash=? AND expires_at>?",
  )
    .bind(
      await hashToken(agentToken),
      agentExpiresAt,
      principal.id,
      principal.hash,
      timestamp(),
    )
    .run();
  if (result.meta.changes !== 1) throw privateError();
  return { agentToken, agentExpiresAt };
}
export async function deleteScan(env: Env, principal: ScanPrincipal) {
  requireRole(principal, "owner");
  const result = await env.DB.prepare(
    "DELETE FROM agent_scan WHERE id=? AND owner_hash=? AND expires_at>?",
  )
    .bind(principal.id, principal.hash, timestamp())
    .run();
  if (result.meta.changes !== 1) throw privateError();
  return { deleted: true };
}
async function mutateScan(
  env: Env,
  principal: ScanPrincipal,
  input: { revision: number; operationId: string },
  kind: string,
  fingerprintBody: unknown,
  transform: (data: ScanPayload) => { data: ScanPayload; message: string },
) {
  requireRole(principal, "agent");
  if (/\bpal_[A-Za-z0-9_-]{43}\b/.test(JSON.stringify(fingerprintBody)))
    throw new AppError(
      "SECRET_REJECTED",
      "Never store scan access keys in evidence, notes or source URLs.",
    );
  const { row, data } = await loadScan(env, principal);
  const fingerprint = await hashToken(
    JSON.stringify({ kind, input: fingerprintBody }),
  );
  const previous = data.operations.find(
    (operation) => operation.id === input.operationId,
  );
  if (previous) {
    if (previous.fingerprint !== fingerprint)
      throw new AppError(
        "OPERATION_CONFLICT",
        "Use a new operationId for a different update.",
        409,
      );
    return publicState(row, data);
  }
  if (row.revision !== input.revision)
    throw new AppError(
      "REVISION_CONFLICT",
      "The scan changed. Read it again and retry with its current revision and a new operationId.",
      409,
    );
  if (data.status === "complete" && kind !== "scan.began")
    throw new AppError(
      "SCAN_COMPLETE",
      "Begin a new scan pass before adding more evidence.",
      409,
    );
  let transformed: ReturnType<typeof transform>;
  try {
    transformed = transform(data);
  } catch (error) {
    if (error instanceof AppError || error instanceof z.ZodError) throw error;
    throw new AppError(
      "INVALID_STATE",
      error instanceof Error ? error.message : "Invalid scan update.",
    );
  }
  const now = timestamp();
  const next = ScanPayloadSchema.parse({
    ...transformed.data,
    workspace: { ...transformed.data.workspace, updatedAt: now },
    activity: [
      ...data.activity,
      { id: crypto.randomUUID(), kind, message: transformed.message, at: now },
    ].slice(-80),
    operations: [
      ...data.operations,
      { id: input.operationId, fingerprint },
    ].slice(-100),
  });
  if (new TextEncoder().encode(JSON.stringify(next)).byteLength > 900_000)
    throw new AppError(
      "SCAN_LIMIT",
      "This scan has reached its size limit. Start a new scan for additional evidence.",
      413,
    );
  const payload = await encrypt(
    next,
    env.DATA_ENCRYPTION_KEY,
    `scan:${principal.id}`,
  );
  const result = await env.DB.prepare(
    "UPDATE agent_scan SET payload=?,revision=revision+1 WHERE id=? AND revision=? AND agent_hash=? AND agent_expires_at>? AND expires_at>?",
  )
    .bind(payload, principal.id, row.revision, principal.hash, now, now)
    .run();
  if (result.meta.changes !== 1)
    throw new AppError(
      "REVISION_CONFLICT",
      "The scan changed or this agent access expired. Read it again before retrying.",
      409,
    );
  return publicState({ ...row, revision: row.revision + 1 }, next);
}
const writing = (data: ScanPayload) => ({
  ...data,
  status: "running" as const,
  run: Math.max(1, data.run),
});

export function getScanService(env: Env, principal: ScanPrincipal) {
  return {
    async request(
      method: "GET" | "POST" | "PATCH" | "DELETE",
      path: string,
      body?: unknown,
    ): Promise<unknown> {
      if (method === "GET" && path === "/") return readScan(env, principal);
      if (method === "GET" && path === "/catalog")
        return {
          categories: CATEGORIES,
          checks: CHECKS,
          catalogVersion: CATALOG_VERSION,
          scoreVersion: SCORE_VERSION,
          target: { score: 85, coverage: 90, criticalGaps: 0 },
          evidencePolicy:
            "Agent submissions are guided observations, not platform-verified collectors. Keep provenance, observed facts and unknowns explicit. Actions and public research never change the score on their own.",
        };
      if (method === "POST" && path === "/agent-token") {
        ScanInputs.empty.parse(body ?? {});
        return rotateScanAgent(env, principal);
      }
      if (method === "DELETE" && path === "/") {
        ScanInputs.delete.parse(body);
        return deleteScan(env, principal);
      }
      requireRole(principal, "agent");
      if (method === "POST" && path === "/begin") {
        const input = ScanInputs.begin.parse(body);
        return mutateScan(
          env,
          principal,
          input,
          "scan.began",
          input,
          (data) => ({
            data: {
              ...data,
              status: "running",
              phase: "Checking your security",
              message: "Your agent is working through the audit.",
              completedAt: undefined,
              run:
                data.status === "complete"
                  ? data.run + 1
                  : Math.max(1, data.run),
            },
            message: data.run
              ? "Agent resumed the audit."
              : "Agent started the audit.",
          }),
        );
      }
      if (method === "POST" && path === "/assets") {
        const input = ScanInputs.asset.parse(body),
          { revision, operationId, ...asset } = input;
        return mutateScan(
          env,
          principal,
          input,
          "asset.added",
          input,
          (data) => ({
            data: {
              ...writing(data),
              workspace: addAsset(data.workspace, asset),
            },
            message: `Added ${asset.label}.`,
          }),
        );
      }
      if (method === "PATCH" && /^\/assets\/[^/]+$/.test(path)) {
        const input = ScanInputs.updateAsset.parse({
          ...(body as object),
          assetId: decodeURIComponent(path.slice(8)),
        });
        return mutateScan(
          env,
          principal,
          input,
          "asset.updated",
          input,
          (data) => ({
            data: {
              ...writing(data),
              workspace: updateAsset(
                data.workspace,
                input.assetId,
                input.patch,
              ),
            },
            message:
              "Updated an asset; affected checks need fresh verification.",
          }),
        );
      }
      if (method === "POST" && path === "/evidence") {
        const input = ScanInputs.evidence.parse(body),
          { revision, operationId, source, ...observation } = input;
        return mutateScan(
          env,
          principal,
          input,
          "evidence.recorded",
          input,
          (data) => ({
            data: {
              ...writing(data),
              workspace: recordEvidence(data.workspace, {
                ...observation,
                method: "guided",
                facts: {
                  ...observation.facts,
                  source_kind: source.kind,
                  source_label: source.label,
                  ...(source.url ? { source_url: source.url } : {}),
                },
              }),
            },
            message: `Checked ${CHECKS.find((check) => check.id === input.checkId)!.title}.`,
          }),
        );
      }
      if (method === "POST" && path === "/actions") {
        const input = ScanInputs.action.parse(body),
          { revision, operationId, ...action } = input;
        return mutateScan(
          env,
          principal,
          input,
          "action.recorded",
          input,
          (data) => ({
            data: {
              ...writing(data),
              workspace: recordAction(data.workspace, action),
            },
            message: `${input.status === "completed" ? "Completed" : "Planned"} a mitigation; verification remains separate.`,
          }),
        );
      }
      if (method === "POST" && path === "/progress") {
        const input = ScanInputs.progress.parse(body);
        return mutateScan(
          env,
          principal,
          input,
          "scan.progress",
          input,
          (data) => ({
            data: {
              ...data,
              run: Math.max(1, data.run),
              status: input.status,
              phase: input.phase,
              message: input.message,
            },
            message: input.message,
          }),
        );
      }
      if (method === "POST" && path === "/context") {
        const input = ScanInputs.context.parse(body);
        return mutateScan(
          env,
          principal,
          input,
          "context.added",
          input,
          (data) => ({
            data: {
              ...writing(data),
              workspace: {
                ...data.workspace,
                threatEvents: [
                  ...data.workspace.threatEvents,
                  {
                    id: crypto.randomUUID(),
                    source: "web",
                    title: input.title,
                    description: input.description,
                    url: input.url,
                    publishedAt: input.publishedAt,
                    ingestedAt: timestamp(),
                    relevance: "unassessed",
                  },
                ],
              },
            },
            message:
              "Added public research for context; it does not establish personal compromise.",
          }),
        );
      }
      if (method === "POST" && path === "/complete") {
        const input = ScanInputs.complete.parse(body);
        return mutateScan(
          env,
          principal,
          input,
          "scan.completed",
          input,
          (data) => ({
            data: {
              ...data,
              workspace: createSnapshot(data.workspace),
              status: "complete",
              phase: "Audit pass complete",
              message: input.summary,
              completedAt: timestamp(),
              run: Math.max(1, data.run),
            },
            message: input.summary,
          }),
        );
      }
      throw new AppError("NOT_FOUND", "Scan endpoint not found.", 404);
    },
  };
}
