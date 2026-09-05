import { z } from "zod";
import {
  WorkspaceSchema,
  EvaluationSchema,
  type Workspace,
  type Evaluation,
} from "@palisade/core";

const Token = z
  .string()
  .min(32)
  .max(256)
  .regex(/^[A-Za-z0-9_-]+$/);
export const BootstrapSchema = z.object({
  id: z.string().uuid(),
  readToken: Token,
  agentToken: Token,
  ownerToken: Token,
  expiresAt: z.string(),
  agentExpiresAt: z.string(),
  viewUrl: z.string().url(),
  mcpUrl: z.string().url(),
});
export type BootstrapScan = z.infer<typeof BootstrapSchema>;
export const ScanStateSchema = z.object({
  scan: z.object({
    id: z.string(),
    status: z.enum([
      "waiting",
      "running",
      "waiting_for_user",
      "blocked",
      "complete",
    ]),
    phase: z.string(),
    message: z.string(),
    createdAt: z.string(),
    updatedAt: z.string(),
    expiresAt: z.string(),
    completedAt: z.string().optional(),
    run: z.number(),
  }),
  workspace: WorkspaceSchema,
  evaluation: EvaluationSchema,
  revision: z.number(),
  activity: z.array(
    z.object({
      id: z.string(),
      kind: z.string(),
      message: z.string(),
      at: z.string(),
    }),
  ),
  target: z
    .object({
      score: z.number(),
      coverage: z.number(),
      met: z.boolean(),
      criticalGaps: z.number(),
    })
    .optional(),
});
export type ScanState = Omit<
  z.infer<typeof ScanStateSchema>,
  "workspace" | "evaluation"
> & { workspace: Workspace; evaluation: Evaluation };

export class ScanError extends Error {
  constructor(
    message: string,
    public status = 0,
  ) {
    super(message);
  }
  get terminal() {
    return [401, 403, 404, 410].includes(this.status);
  }
}

export async function scanRequest<T>(
  path: string,
  options: {
    token?: string;
    method?: string;
    body?: unknown;
    schema: z.ZodType<T>;
    signal?: AbortSignal;
  },
): Promise<T> {
  const headers: Record<string, string> = {};
  if (options.token) headers.Authorization = `Bearer ${options.token}`;
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  let response: Response;
  try {
    response = await fetch(path, {
      method: options.method ?? "GET",
      headers,
      body:
        options.body === undefined ? undefined : JSON.stringify(options.body),
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      signal: options.signal
        ? AbortSignal.any([options.signal, AbortSignal.timeout(15_000)])
        : AbortSignal.timeout(15_000),
    });
  } catch (error) {
    if (options.signal?.aborted) throw error;
    throw new ScanError(
      "Couldn’t connect. Check your connection and try again.",
    );
  }
  if (!response.ok) {
    if ([401, 403].includes(response.status))
      throw new ScanError(
        "This private scan link is missing its access key, or the key has expired.",
        response.status,
      );
    if ([404, 410].includes(response.status))
      throw new ScanError(
        "This scan has expired or been deleted.",
        response.status,
      );
    if (response.status === 429)
      throw new ScanError(
        "Too many requests. Give it a moment, then try again.",
        429,
      );
    throw new ScanError(
      "The scan service couldn’t respond. Try again in a moment.",
      response.status,
    );
  }
  const body: unknown = await response.json().catch(() => {
    throw new ScanError(
      "The scan service returned an unreadable response. Please try again.",
    );
  });
  const parsed = options.schema.safeParse(body);
  if (!parsed.success)
    throw new ScanError(
      "The scan service returned an unexpected response. Please reload to try again.",
    );
  return parsed.data;
}

const PREFIX = "palisade.scan.";
const memory = new Map<string, BootstrapScan>();

export function saveScan(scan: BootstrapScan): boolean {
  memory.set(scan.id, scan);
  try {
    localStorage.setItem(PREFIX + scan.id, JSON.stringify(scan));
    localStorage.setItem(PREFIX + "latest", scan.id);
    return true;
  } catch {
    return false;
  }
}
export function loadScan(id: string): BootstrapScan | undefined {
  if (memory.has(id)) return memory.get(id);
  try {
    const value = JSON.parse(localStorage.getItem(PREFIX + id) ?? "null");
    const result = BootstrapSchema.safeParse(value);
    if (result.success && result.data.id === id) {
      memory.set(id, result.data);
      return result.data;
    }
  } catch {
    /* Browsers may deny persistence; the private fragment still permits reading. */
  }
}
export function latestScan(): BootstrapScan | undefined {
  try {
    const id = localStorage.getItem(PREFIX + "latest");
    const scan = id ? loadScan(id) : undefined;
    return scan && Date.parse(scan.expiresAt) > Date.now() ? scan : undefined;
  } catch {
    return undefined;
  }
}
export function forgetScan(id: string) {
  memory.delete(id);
  try {
    localStorage.removeItem(PREFIX + id);
    if (localStorage.getItem(PREFIX + "latest") === id)
      localStorage.removeItem(PREFIX + "latest");
  } catch {
    /* Deletion has already completed on the server. */
  }
}
export function readCapability(hash: string): string | undefined {
  const parsed = Token.safeParse(
    new URLSearchParams(hash.replace(/^#/, "")).get("key"),
  );
  return parsed.success ? parsed.data : undefined;
}
export function privateScanPath(scan: Pick<BootstrapScan, "id" | "readToken">) {
  return `/scan/${encodeURIComponent(scan.id)}#key=${encodeURIComponent(scan.readToken)}`;
}
export function safeSourceUrl(url: unknown): string | undefined {
  if (typeof url !== "string") return undefined;
  try {
    const parsed = new URL(url);
    return parsed.protocol === "https:" && !parsed.username && !parsed.password
      ? parsed.href
      : undefined;
  } catch {
    return undefined;
  }
}
export async function copyText(value: string): Promise<boolean> {
  try {
    if (!navigator.clipboard?.writeText) return false;
    await navigator.clipboard.writeText(value);
    return true;
  } catch {
    return false;
  }
}
export async function refreshAgent(
  scan: BootstrapScan,
): Promise<BootstrapScan> {
  if (Date.parse(scan.agentExpiresAt) > Date.now() + 60_000) {
    try {
      await scanRequest(`/api/scans/${scan.id}`, {
        token: scan.agentToken,
        schema: ScanStateSchema,
      });
      return scan;
    } catch (error) {
      // Another tab may have rotated a credential that is still unexpired locally.
      // Preserve working agent connections; rotate only after an access rejection.
      if (!(error instanceof ScanError) || ![401, 403].includes(error.status))
        throw error;
    }
  }
  const token = await scanRequest(`/api/scans/${scan.id}/agent-token`, {
    token: scan.ownerToken,
    method: "POST",
    body: {},
    schema: z.object({ agentToken: Token, agentExpiresAt: z.string() }),
  });
  const updated = { ...scan, ...token };
  saveScan(updated);
  return updated;
}
