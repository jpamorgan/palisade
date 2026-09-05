import { createAuth } from "./auth";
import { hashToken } from "./crypto";
import { AppError, type Env, type Principal } from "./env";

export function validateOrigin(request: Request, env: Env) {
  const origin = request.headers.get("origin");
  const allowed = [new URL(env.APP_URL).origin];
  if (allowed[0]!.startsWith("http://localhost"))
    allowed.push("http://localhost:5173", "http://localhost:3000");
  if (origin && !allowed.includes(origin))
    throw new AppError(
      "ORIGIN_REJECTED",
      "This request came from an untrusted origin.",
      403,
    );
  if (
    !["GET", "HEAD", "OPTIONS"].includes(request.method) &&
    !request.headers.get("authorization") &&
    !origin
  )
    throw new AppError(
      "ORIGIN_REQUIRED",
      "Browser requests must include their origin. Agents must use an API token.",
      403,
    );
}
export async function authenticate(
  request: Request,
  env: Env,
): Promise<Principal> {
  const authorization = request.headers.get("authorization");
  if (authorization) {
    if (!/^Bearer pal_[a-zA-Z0-9_-]{43}$/.test(authorization))
      throw new AppError("UNAUTHORIZED", "Invalid API token.", 401);
    const hash = await hashToken(authorization.slice(7));
    const row = await env.DB.prepare(
      "SELECT t.id AS token_id,t.owner_id,t.scopes,t.expires_at,u.name,u.email,u.email_verified FROM api_token t JOIN user u ON u.id=t.owner_id WHERE t.hash=?",
    )
      .bind(hash)
      .first<{
        token_id: string;
        owner_id: string;
        scopes: string;
        expires_at: string;
        name: string;
        email: string;
        email_verified: number;
      }>();
    if (!row || Date.parse(row.expires_at) <= Date.now())
      throw new AppError(
        "UNAUTHORIZED",
        "Your API token is invalid, expired, or revoked.",
        401,
      );
    await env.DB.prepare("UPDATE api_token SET last_used_at=? WHERE id=?")
      .bind(new Date().toISOString(), row.token_id)
      .run();
    return {
      id: row.owner_id,
      email: row.email,
      name: row.name,
      emailVerified: Boolean(row.email_verified),
      scopes: JSON.parse(row.scopes),
      source: "token",
    };
  }
  const result = await createAuth(env).api.getSession({
    headers: request.headers,
  });
  if (!result)
    throw new AppError(
      "UNAUTHORIZED",
      "Sign in to access your security workspace.",
      401,
    );
  return {
    id: result.user.id,
    name: result.user.name,
    email: result.user.email,
    emailVerified: result.user.emailVerified,
    scopes: ["read", "write", "scan"],
    source: "session",
    sessionCreatedAt: result.session.createdAt,
  };
}
export function requireScope(principal: Principal, scope: string) {
  if (!principal.scopes.includes(scope))
    throw new AppError(
      "FORBIDDEN",
      `This token requires the ${scope} scope.`,
      403,
    );
}
export function requireSession(principal: Principal, fresh = false) {
  if (principal.source !== "session")
    throw new AppError(
      "SESSION_REQUIRED",
      "Manage this setting from the signed-in web application.",
      403,
    );
  if (
    fresh &&
    (!principal.sessionCreatedAt ||
      Date.now() - new Date(principal.sessionCreatedAt).getTime() >
        60 * 60 * 1000)
  )
    throw new AppError(
      "FRESH_SESSION_REQUIRED",
      "Sign in again before changing this sensitive setting.",
      403,
    );
}
