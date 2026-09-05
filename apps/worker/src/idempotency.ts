import { AppError, type Env } from "./env";
import { encrypt, decrypt, hashToken } from "./crypto";

export async function idempotent(
  env: Env,
  owner: string,
  key: string | undefined,
  method: string,
  path: string,
  body: unknown,
  run: () => Promise<unknown>,
) {
  if (!key) return run();
  if (!/^[A-Za-z0-9._:-]{8,100}$/.test(key))
    throw new AppError(
      "INVALID_IDEMPOTENCY_KEY",
      "Use an 8–100 character stable operation identifier.",
    );
  // Credentials are returned once and never persisted in an idempotency response.
  if (path === "/workspace" && method === "DELETE") return run();
  const fingerprint = await hashToken(JSON.stringify({ method, path, body }));
  const existing = await env.DB.prepare(
    "SELECT fingerprint,status,payload FROM operation WHERE owner_id=? AND key=?",
  )
    .bind(owner, key)
    .first<{ fingerprint: string; status: string; payload: string | null }>();
  if (existing) {
    if (existing.fingerprint !== fingerprint)
      throw new AppError(
        "IDEMPOTENCY_CONFLICT",
        "This operation key was already used with different input.",
        409,
      );
    if (existing.status === "credential-issued")
      throw new AppError(
        "TOKEN_ALREADY_ISSUED",
        "This token was already created and displayed once. Revoke it in Settings if you did not save it.",
        409,
      );
    if (existing.status !== "complete" || !existing.payload)
      throw new AppError(
        "OPERATION_PENDING",
        "This operation is in progress or requires review. Refresh your workspace before retrying.",
        409,
      );
    return decrypt(
      existing.payload,
      env.DATA_ENCRYPTION_KEY,
      `${owner}/operation/${key}`,
    );
  }
  const inserted = await env.DB.prepare(
    "INSERT OR IGNORE INTO operation(owner_id,key,fingerprint,status,created_at) VALUES(?,?,?,'pending',?)",
  )
    .bind(owner, key, fingerprint, new Date().toISOString())
    .run();
  if (inserted.meta.changes !== 1)
    throw new AppError(
      "OPERATION_PENDING",
      "Another request is processing this operation.",
      409,
    );
  try {
    const result = await run();
    if (path === "/tokens") {
      await env.DB.prepare(
        "UPDATE operation SET status='credential-issued' WHERE owner_id=? AND key=?",
      )
        .bind(owner, key)
        .run();
      return result;
    }
    const payload = await encrypt(
      result,
      env.DATA_ENCRYPTION_KEY,
      `${owner}/operation/${key}`,
    );
    await env.DB.prepare(
      "UPDATE operation SET status='complete',payload=? WHERE owner_id=? AND key=?",
    )
      .bind(payload, owner, key)
      .run();
    return result;
  } catch (error) {
    // Invalid requests are safe to correct and retry; uncertain partial failures remain reserved.
    if (error instanceof AppError && error.status < 500)
      await env.DB.prepare("DELETE FROM operation WHERE owner_id=? AND key=?")
        .bind(owner, key)
        .run();
    throw error;
  }
}
