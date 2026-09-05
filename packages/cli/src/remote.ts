import { PalisadeError } from "./errors";
export type RequestMethod = "GET" | "POST" | "PATCH" | "DELETE";
export interface AuditService {
  request(
    method: RequestMethod,
    path: string,
    body?: unknown,
  ): Promise<unknown>;
}

export function normalizeHost(host: string): string {
  let url: URL;
  try {
    url = new URL(host);
  } catch {
    throw new PalisadeError(
      "INVALID_HOST",
      "Host must be an HTTPS URL (or HTTP on localhost).",
      2,
    );
  }
  if (
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    !["", "/"].includes(url.pathname)
  )
    throw new PalisadeError(
      "INVALID_HOST",
      "Host must be a base origin with no credentials, path, query, or fragment.",
      2,
    );
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(loopback && url.protocol === "http:"))
    throw new PalisadeError(
      "INSECURE_HOST",
      "Remote hosts require HTTPS. HTTP is allowed only on localhost.",
      2,
    );
  return url.origin;
}
export class RemoteService implements AuditService {
  private readonly host: string;
  constructor(
    host: string,
    private readonly token: string | undefined,
    private readonly fetcher: typeof fetch = fetch,
  ) {
    this.host = normalizeHost(host);
  }
  async request(
    method: RequestMethod,
    path: string,
    body?: unknown,
  ): Promise<unknown> {
    if (!/^\/[a-z][a-zA-Z0-9/_.:-]*$/.test(path))
      throw new PalisadeError("INVALID_PATH", "Invalid API operation.", 2);
    if (!this.token && path !== "/catalog")
      throw new PalisadeError(
        "TOKEN_REQUIRED",
        "Set PALISADE_TOKEN to a hosted API token. Tokens are never saved in the local workspace.",
        2,
      );
    let response: Response;
    try {
      response = await this.fetcher(this.host + "/api/v1" + path, {
        method,
        headers: {
          Accept: "application/json",
          ...(this.token ? { Authorization: `Bearer ${this.token}` } : {}),
          ...(body === undefined ? {} : { "Content-Type": "application/json" }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        redirect: "error",
        signal: AbortSignal.timeout(25_000),
      });
    } catch {
      throw new PalisadeError(
        "NETWORK_ERROR",
        "Could not reach the hosted platform. Check its address and your connection.",
      );
    }
    if (Number(response.headers.get("content-length")) > 8 * 1024 * 1024)
      throw new PalisadeError(
        "RESPONSE_TOO_LARGE",
        "The platform response exceeds the 8 MiB safety limit.",
      );
    const reader = response.body?.getReader();
    let length = 0;
    const chunks: Uint8Array[] = [];
    try {
      if (reader)
        for (;;) {
          const part = await reader.read();
          if (part.done) break;
          length += part.value.byteLength;
          if (length > 8 * 1024 * 1024) {
            await reader.cancel();
            throw new PalisadeError(
              "RESPONSE_TOO_LARGE",
              "The platform response exceeds the 8 MiB safety limit.",
            );
          }
          chunks.push(part.value);
        }
    } catch (error) {
      if (error instanceof PalisadeError) throw error;
      throw new PalisadeError(
        "NETWORK_ERROR",
        "The platform response was interrupted. Retry the operation after checking your connection.",
      );
    } finally {
      reader?.releaseLock();
    }
    const raw = Buffer.concat(chunks).toString("utf8");
    let data: any;
    try {
      data = JSON.parse(raw);
    } catch {
      throw new PalisadeError(
        "INVALID_RESPONSE",
        `Platform returned an unexpected response (HTTP ${response.status}).`,
      );
    }
    if (!response.ok) {
      const safe = (value: unknown, fallback: string) =>
        typeof value === "string"
          ? (this.token
              ? value.replaceAll(this.token, "[redacted]")
              : value
            ).slice(0, 2000)
          : fallback;
      throw new PalisadeError(
        safe(data?.error?.code, "HTTP_ERROR"),
        safe(data?.error?.message, `Request failed (HTTP ${response.status}).`),
        response.status === 401 || response.status === 403 ? 3 : 1,
      );
    }
    return data;
  }
}
