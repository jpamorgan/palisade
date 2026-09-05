import {
  createWorkspace,
  evaluateWorkspace,
  WorkspaceSchema,
  type Workspace,
} from "@palisade/core";
import { encrypt, decrypt } from "./crypto";
import { AppError, type Env, type Principal } from "./env";

export async function getWorkspace(env: Env, principal: Principal) {
  let row = await env.DB.prepare(
    "SELECT payload,revision FROM workspace WHERE owner_id=?",
  )
    .bind(principal.id)
    .first<{ payload: string; revision: number }>();
  if (!row) {
    const workspace = createWorkspace(
      `${principal.name.split(" ")[0] || "My"}’s security`,
    );
    const payload = await encrypt(
      workspace,
      env.DATA_ENCRYPTION_KEY,
      principal.id,
    );
    await env.DB.prepare(
      "INSERT OR IGNORE INTO workspace(owner_id,payload,revision,monitoring,updated_at) VALUES(?,?,1,0,?)",
    )
      .bind(principal.id, payload, workspace.updatedAt)
      .run();
    row = await env.DB.prepare(
      "SELECT payload,revision FROM workspace WHERE owner_id=?",
    )
      .bind(principal.id)
      .first<{ payload: string; revision: number }>();
  }
  if (!row)
    throw new AppError(
      "STORE_UNAVAILABLE",
      "Could not initialize your workspace.",
      503,
    );
  const workspace = await decrypt<Workspace>(
    row.payload,
    env.DATA_ENCRYPTION_KEY,
    principal.id,
  );
  return {
    workspace,
    evaluation: evaluateWorkspace(workspace),
    revision: row.revision,
  };
}
export async function mutateWorkspace(
  env: Env,
  principal: Principal,
  transform: (workspace: Workspace) => Workspace,
  expectedRevision?: number,
) {
  for (let attempt = 0; attempt < 3; attempt++) {
    const current = await getWorkspace(env, principal);
    if (expectedRevision !== undefined && current.revision !== expectedRevision)
      throw new AppError(
        "REVISION_CONFLICT",
        "Your workspace changed. Refresh and try again.",
        409,
      );
    let workspace: Workspace;
    try {
      workspace = WorkspaceSchema.parse({
        ...transform(current.workspace),
        updatedAt: new Date().toISOString(),
      });
    } catch (error) {
      if (error instanceof Error && error.name !== "ZodError")
        throw new AppError("INVALID_STATE", error.message);
      throw error;
    }
    if (
      new TextEncoder().encode(JSON.stringify(workspace)).byteLength > 1_000_000
    )
      throw new AppError(
        "WORKSPACE_LIMIT",
        "This workspace has reached its 1 MB limit. Export a backup, then remove older snapshots from Audit history.",
        413,
      );
    const payload = await encrypt(
      workspace,
      env.DATA_ENCRYPTION_KEY,
      principal.id,
    );
    const result = await env.DB.prepare(
      "UPDATE workspace SET payload=?,revision=revision+1,monitoring=?,updated_at=? WHERE owner_id=? AND revision=?",
    )
      .bind(
        payload,
        workspace.settings.monitoring ? 1 : 0,
        workspace.updatedAt,
        principal.id,
        current.revision,
      )
      .run();
    if (result.meta.changes === 1)
      return {
        workspace,
        evaluation: evaluateWorkspace(workspace),
        revision: current.revision + 1,
      };
  }
  throw new AppError(
    "REVISION_CONFLICT",
    "Another update is in progress. Please retry.",
    409,
  );
}
export async function logActivity(
  env: Env,
  userId: string,
  action: string,
  summary: string,
) {
  await env.DB.prepare(
    "INSERT INTO activity(id,owner_id,action,summary,created_at) VALUES(?,?,?,?,?)",
  )
    .bind(
      crypto.randomUUID(),
      userId,
      action,
      summary,
      new Date().toISOString(),
    )
    .run();
}
export async function getIntegration<T>(
  env: Env,
  userId: string,
  provider: string,
): Promise<T | null> {
  const row = await env.DB.prepare(
    "SELECT payload FROM integration WHERE owner_id=? AND provider=?",
  )
    .bind(userId, provider)
    .first<{ payload: string }>();
  return row
    ? decrypt<T>(row.payload, env.DATA_ENCRYPTION_KEY, `${userId}/${provider}`)
    : null;
}
export async function setIntegration(
  env: Env,
  userId: string,
  provider: string,
  value: unknown,
) {
  const payload = await encrypt(
    value,
    env.DATA_ENCRYPTION_KEY,
    `${userId}/${provider}`,
  );
  await env.DB.prepare(
    "INSERT INTO integration(owner_id,provider,payload) VALUES(?,?,?) ON CONFLICT(owner_id,provider) DO UPDATE SET payload=excluded.payload",
  )
    .bind(userId, provider, payload)
    .run();
}
export async function rateLimit(
  env: Env,
  subject: string,
  maximum: number,
  windowSeconds: number,
) {
  // Epoch seconds keep cleanup correct across minute and hour rate limits.
  const window =
    Math.floor(Date.now() / (windowSeconds * 1000)) * windowSeconds;
  const result = await env.DB.prepare(
    "INSERT INTO request_limit(key,count,window) VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN window=excluded.window THEN count+1 ELSE 1 END,window=excluded.window RETURNING count",
  )
    .bind(subject, window)
    .first<{ count: number }>();
  if ((result?.count ?? maximum + 1) > maximum)
    throw new AppError(
      "RATE_LIMITED",
      "Too many requests. Please wait before trying again.",
      429,
    );
}
