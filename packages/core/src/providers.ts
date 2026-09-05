import { z } from "zod";
import { isoNow, recordEvidence } from "./engine";
import { ThreatEventSchema, WorkspaceSchema } from "./validation";
import type {
  Breach,
  FootprintResult,
  HibpResult,
  ProviderOptions,
  ProviderReceipt,
  ProviderSourceDiagnostic,
  ThreatEvent,
  ThreatFeedResult,
  Workspace,
} from "./types";

const HIBP = "https://haveibeenpwned.com/api/v3";
const CISA =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const BRAVE = "https://api.search.brave.com/res/v1/web/search";
const userAgent = "Palisade-Personal-Security-Audit/0.1";
class ProviderFailure extends Error {
  constructor(
    readonly code: NonNullable<ProviderSourceDiagnostic["code"]>,
    readonly httpStatus?: number,
  ) {
    super(code);
  }
}
function publicSourceFailure(
  source: ProviderSourceDiagnostic["source"],
  reason: unknown,
): ProviderSourceDiagnostic {
  const base = { source, status: "unavailable" as const };
  if (reason instanceof ProviderFailure)
    return {
      ...base,
      code: reason.code,
      errorName: "Error",
      ...(reason.httpStatus === undefined
        ? {}
        : { httpStatus: reason.httpStatus }),
    };
  if (reason instanceof z.ZodError)
    return { ...base, code: "invalid_schema", errorName: "ZodError" };
  if (reason instanceof SyntaxError)
    return { ...base, code: "invalid_json", errorName: "SyntaxError" };
  if (reason instanceof TypeError)
    return {
      ...base,
      code: /^Illegal invocation\b/.test(reason.message)
        ? "illegal_invocation"
        : "request_error",
      errorName: "TypeError",
    };
  if (reason instanceof DOMException && reason.name === "AbortError")
    return { ...base, code: "timeout", errorName: "AbortError" };
  return {
    ...base,
    code: "unknown_error",
    errorName: reason instanceof Error ? "Error" : "UnknownError",
  };
}
const textOnly = (value: string, max = 2000) =>
  value
    .replace(/<[^>]*>/g, "")
    .replace(
      /&(?:amp|lt|gt|quot|#39);/g,
      (entity) =>
        ({
          "&amp;": "&",
          "&lt;": "<",
          "&gt;": ">",
          "&quot;": '"',
          "&#39;": "'",
        })[entity] ?? entity,
    )
    .slice(0, max);
const publicUrl = (value: string): boolean => {
  try {
    const url = new URL(value);
    return (
      url.protocol === "https:" &&
      !url.username &&
      !url.password &&
      !/^(?:localhost|127\.|0\.|10\.|192\.168\.|169\.254\.|\[|.*\.local$)/i.test(
        url.hostname,
      ) &&
      !/^172\.(?:1[6-9]|2\d|3[01])\./.test(url.hostname)
    );
  } catch {
    return false;
  }
};
const stablePart = (value: string) => {
  let hash = 14695981039346656037n;
  for (const byte of new TextEncoder().encode(value)) {
    hash ^= BigInt(byte);
    hash = BigInt.asUintN(64, hash * 1099511628211n);
  }
  return hash.toString(16).padStart(16, "0");
};

/** Only fixed provider endpoints call this function. Redirects are never followed with credentials. */
async function boundedJson(
  url: string,
  options: ProviderOptions,
  headers: Record<string, string> = {},
  maxBytes = 8_000_000,
): Promise<{ response: Response; data: unknown }> {
  if (
    !(url.startsWith(`${HIBP}/`) || url === CISA || url.startsWith(`${BRAVE}?`))
  )
    throw new Error("Unsupported provider endpoint.");
  const controller = new AbortController(),
    timeoutMs = Math.max(50, Math.min(options.timeoutMs ?? 10_000, 20_000));
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new ProviderFailure("timeout"));
    }, timeoutMs);
  });
  const operation = (async () => {
    const init: RequestInit = {
      headers: {
        accept: "application/json",
        "user-agent": userAgent,
        ...headers,
      },
      signal: controller.signal,
      // Workers rejects redirect:"error" at runtime. Manual preserves the same
      // no-follow boundary: every 3xx returns unassessed before body parsing.
      redirect: "manual",
    };
    const response = options.fetch
      ? await options.fetch(url, init)
      : await globalThis.fetch(url, init);
    if (!response.ok) return { response, data: null };
    if (Number(response.headers.get("content-length") ?? 0) > maxBytes)
      throw new ProviderFailure("response_too_large", response.status);
    if (!response.body)
      throw new ProviderFailure("empty_response", response.status);
    const reader = response.body.getReader(),
      chunks: Uint8Array[] = [];
    let length = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        length += value.byteLength;
        if (length > maxBytes) {
          controller.abort();
          throw new ProviderFailure("response_too_large", response.status);
        }
        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }
    const bytes = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.length;
    }
    return {
      response,
      data: JSON.parse(new TextDecoder().decode(bytes)) as unknown,
    };
  })();
  try {
    return await Promise.race([operation, timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function httpReceipt(response: Response, provider: string): ProviderReceipt {
  const retry = Number(response.headers.get("retry-after"));
  if (response.status === 429)
    return {
      status: "unavailable",
      message: `${provider} rate limit reached. Retry later.`,
      ...(Number.isFinite(retry) && retry > 0
        ? { retryAfterSeconds: Math.min(Math.ceil(retry), 86400) }
        : {}),
    };
  if (response.status === 401 || response.status === 403)
    return {
      status: "unavailable",
      message: `${provider} rejected authentication or this subscription lacks access.`,
    };
  return {
    status: "error",
    message: `${provider} returned HTTP ${response.status}. The check is unassessed.`,
  };
}
function failureReceipt(): ProviderReceipt {
  return {
    status: "unavailable",
    message:
      "Provider could not be reached or returned an invalid response. No clean result was inferred.",
  };
}
const BreachSchema = z.object({
  Name: z.string().min(1).max(200),
  Title: z.string().max(500),
  Domain: z.string().max(300),
  BreachDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  AddedDate: z.string().datetime({ offset: true }),
  DataClasses: z.array(z.string().max(200)).max(100),
  IsVerified: z.boolean(),
});
const convertBreach = (b: z.infer<typeof BreachSchema>): Breach => ({
  name: b.Name,
  title: textOnly(b.Title, 500),
  domain: b.Domain,
  breachDate: b.BreachDate,
  addedDate: b.AddedDate,
  dataClasses: b.DataClasses.map((c) => textOnly(c, 200)),
  verified: b.IsVerified,
});
export const HIBP_SCOPE =
  "Exact email lookup disclosed this address to HIBP with consent. Public API coverage excludes sensitive and retired breaches; this is not a search of every leak or stealer log.";

export async function checkHibp(
  email: string,
  apiKey: string,
  options: ProviderOptions & { consent: boolean; ownershipVerified: boolean },
): Promise<HibpResult> {
  const checkedAt = isoNow(options.now),
    base = {
      breaches: [] as Breach[],
      checkedAt,
      scope: HIBP_SCOPE,
      subject: email.trim().toLowerCase(),
    };
  if (!options.consent || !options.ownershipVerified)
    return {
      ...base,
      receipt: {
        status: "unavailable",
        message:
          "Explicit exact-address disclosure consent and email ownership verification are required before querying HIBP.",
      },
    };
  if (!z.email().safeParse(email).success)
    return {
      ...base,
      receipt: {
        status: "error",
        message: "Enter a valid owned email address.",
      },
    };
  if (!/^[a-f0-9]{32}$/i.test(apiKey))
    return {
      ...base,
      receipt: {
        status: "unavailable",
        message:
          "Configure a valid HIBP subscription key before running this check.",
      },
    };
  try {
    const { response, data } = await boundedJson(
      `${HIBP}/breachedaccount/${encodeURIComponent(email.trim().toLowerCase())}?truncateResponse=false&includeUnverified=false`,
      options,
      { "hibp-api-key": apiKey },
      5_000_000,
    );
    if (response.status === 404)
      return {
        ...base,
        receipt: {
          status: "ok",
          message:
            "No match was returned within HIBP's available breach coverage at this time. This does not establish that the address has never leaked.",
        },
      };
    if (!response.ok)
      return { ...base, receipt: httpReceipt(response, "HIBP") };
    const breaches = z
      .array(BreachSchema)
      .max(5000)
      .parse(data)
      .map(convertBreach);
    return {
      ...base,
      breaches,
      receipt: {
        status: "ok",
        message: `HIBP returned ${breaches.length} verified breach record${breaches.length === 1 ? "" : "s"}. Historical exposure and protective remediation are tracked separately.`,
      },
    };
  } catch {
    return { ...base, receipt: failureReceipt() };
  }
}

export function applyHibpResult(
  workspace: Workspace,
  assetId: string,
  result: HibpResult,
  now?: string | Date,
): Workspace {
  const asset = workspace.assets.find((a) => a.id === assetId);
  if (!asset || asset.kind !== "email")
    throw new Error("HIBP results require an email asset in this workspace.");
  if (!asset.value || result.subject !== asset.value.trim().toLowerCase())
    throw new Error(
      "The email identifier changed while the scan was running. Run a new scan for the current asset.",
    );
  const time = isoNow(now);
  let updated = recordEvidence(
    workspace,
    {
      checkId: "exposure.breach-review",
      assetId,
      method: "provider",
      status: result.receipt.status === "ok" ? "pass" : "unknown",
      observedAt: result.checkedAt,
      notes: result.receipt.message,
      facts: {
        provider: "HIBP",
        scope: result.scope,
        breachCount: result.breaches.length,
        adapterVersion: "1.0.0",
      },
    },
    time,
  );
  if (result.receipt.status !== "ok") return updated;
  const events: ThreatEvent[] = result.breaches.map((breach) => ({
    id: `hibp:${stablePart(assetId)}:${stablePart(result.subject)}:${stablePart(breach.name)}`,
    source: "hibp",
    title: breach.title,
    description: `HIBP associates this email with ${breach.title}. Reported data classes: ${breach.dataClasses.join(", ")}. This historical record does not prove current account compromise.`,
    url: `https://haveibeenpwned.com/Breach/${encodeURIComponent(breach.name)}`,
    publishedAt: isoNow(breach.addedDate),
    ingestedAt: time,
    relevance: "confirmed",
    assetId,
    identifiers: [breach.name, ...breach.dataClasses].slice(0, 100),
  }));
  updated = mergeEvents(updated, events, time);
  return updated;
}

const KevSchema = z.object({
  vulnerabilities: z
    .array(
      z.object({
        cveID: z.string().regex(/^CVE-\d{4}-\d{4,}$/),
        vendorProject: z.string().max(500),
        product: z.string().max(500),
        vulnerabilityName: z.string().max(1000),
        dateAdded: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
        shortDescription: z.string().max(10000),
        requiredAction: z.string().max(5000),
      }),
    )
    .max(20_000),
});

export async function fetchThreatFeeds(
  options: ProviderOptions = {},
): Promise<ThreatFeedResult> {
  const checkedAt = isoNow(options.now),
    outcomes = await Promise.allSettled([
      (async () => {
        const { response, data } = await boundedJson(CISA, options);
        if (!response.ok)
          throw new ProviderFailure("http_error", response.status);
        const events = KevSchema.parse(data)
          .vulnerabilities.sort(
            (a, b) =>
              b.dateAdded.localeCompare(a.dateAdded) ||
              a.cveID.localeCompare(b.cveID),
          )
          .slice(0, 40)
          .map((v) => ({
            id: `cisa:${v.cveID}`,
            source: "cisa" as const,
            title: textOnly(`${v.cveID}: ${v.vulnerabilityName}`, 500),
            description: textOnly(
              `${v.vendorProject} ${v.product}. ${v.shortDescription} Required action: ${v.requiredAction}`,
              2800,
            ),
            url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(v.cveID)}`,
            publishedAt: isoNow(`${v.dateAdded}T00:00:00Z`),
            ingestedAt: checkedAt,
            relevance: "unassessed" as const,
            identifiers: [v.cveID],
          }));
        return { events, httpStatus: response.status };
      })(),
      (async () => {
        const { response, data } = await boundedJson(
          `${HIBP}/breaches`,
          options,
          {},
          8_000_000,
        );
        if (!response.ok)
          throw new ProviderFailure("http_error", response.status);
        const events = z
          .array(BreachSchema)
          .max(10000)
          .parse(data)
          .sort(
            (a, b) =>
              b.AddedDate.localeCompare(a.AddedDate) ||
              a.Name.localeCompare(b.Name),
          )
          .slice(0, 20)
          .map((b) => ({
            id: `hibp:catalog:${stablePart(b.Name)}`,
            source: "hibp" as const,
            title: textOnly(b.Title, 500),
            description: textOnly(
              `A cataloged breach involving ${b.Domain || b.Title}. Reported data classes: ${b.DataClasses.join(", ")}. A public report does not establish that you are affected.`,
              2800,
            ),
            url: `https://haveibeenpwned.com/Breach/${encodeURIComponent(b.Name)}`,
            publishedAt: isoNow(b.AddedDate),
            ingestedAt: checkedAt,
            relevance: "unassessed" as const,
            identifiers: [b.Name, ...b.DataClasses].slice(0, 100),
          }));
        return { events, httpStatus: response.status };
      })(),
    ]);
  const events = outcomes
    .flatMap<ThreatEvent>((outcome) =>
      outcome.status === "fulfilled" ? outcome.value.events : [],
    )
    .filter((event) => Date.parse(event.publishedAt) <= Date.parse(checkedAt))
    .filter((event) => ThreatEventSchema.safeParse(event).success)
    .sort(
      (a, b) =>
        b.publishedAt.localeCompare(a.publishedAt) || a.id.localeCompare(b.id),
    );
  const count = outcomes.filter((o) => o.status === "fulfilled").length;
  const sources = outcomes.map<ProviderSourceDiagnostic>((outcome, index) => {
    const source = index === 0 ? "cisa" : "hibp";
    return outcome.status === "fulfilled"
      ? { source, status: "ok", httpStatus: outcome.value.httpStatus }
      : publicSourceFailure(source, outcome.reason);
  });
  return {
    checkedAt,
    events,
    receipt:
      count === 2
        ? {
            status: "ok",
            sources,
            message: `Refreshed CISA KEV and HIBP's public breach catalog (${events.length} recent reports). Personal relevance is unassessed.`,
          }
        : count === 1
          ? {
              status: "unavailable",
              sources,
              message: `One public feed is unavailable. Retained ${events.length} reports from the available feed; this refresh has incomplete source coverage.`,
            }
          : {
              status: "unavailable",
              sources,
              message:
                "Both public threat feeds are unavailable. Previous events were retained; no absence of threats was inferred.",
            },
  };
}

function mergeEvents(
  workspace: Workspace,
  events: ThreatEvent[],
  time: string,
): Workspace {
  const map = new Map(workspace.threatEvents.map((e) => [e.id, e]));
  for (const event of events) {
    const parsed = ThreatEventSchema.parse(event),
      existing = map.get(event.id);
    map.set(
      event.id,
      existing && parsed.relevance !== "confirmed"
        ? { ...parsed, relevance: existing.relevance }
        : parsed,
    );
  }
  if (map.size > 2000)
    throw new Error(
      "Threat history limit reached. Export this audit before starting a new workspace.",
    );
  return WorkspaceSchema.parse({
    ...workspace,
    updatedAt: time,
    threatEvents: [...map.values()],
  });
}
export function applyThreatFeedResult(
  workspace: Workspace,
  result: ThreatFeedResult,
  now?: string | Date,
): Workspace {
  return mergeEvents(
    workspace,
    result.events.map((e) => ({ ...e, relevance: "unassessed" })),
    isoNow(now),
  );
}

export async function searchFootprint(
  query: string,
  apiKey: string,
  options: ProviderOptions & { consent: boolean },
): Promise<FootprintResult> {
  const checkedAt = isoNow(options.now),
    base = {
      results: [],
      checkedAt,
      query: query.trim(),
      scope:
        "Brave Search received the supplied public-identity query with consent. Result count is not a measure of prominence or personal threat. Every identity match needs user review.",
    };
  if (!options.consent)
    return {
      ...base,
      receipt: {
        status: "unavailable",
        message:
          "Explicit consent to send the scoped public identifier to Brave Search is required.",
      },
    };
  if (!apiKey || apiKey.length > 500)
    return {
      ...base,
      receipt: {
        status: "unavailable",
        message:
          "Configure a Brave Search API key before running public-footprint discovery.",
      },
    };
  if (query.trim().length < 2 || query.length > 160)
    return {
      ...base,
      receipt: {
        status: "error",
        message: "Use a public identifier between 2 and 160 characters.",
      },
    };
  try {
    const url = new URL(BRAVE);
    url.searchParams.set("q", query);
    url.searchParams.set("count", "10");
    url.searchParams.set("safesearch", "moderate");
    const { response, data } = await boundedJson(
      url.toString(),
      options,
      { "X-Subscription-Token": apiKey },
      2_000_000,
    );
    if (!response.ok)
      return { ...base, receipt: httpReceipt(response, "Brave Search") };
    const parsed = z
      .object({
        query: z.object({ original: z.string() }),
        web: z
          .object({
            results: z
              .array(
                z.object({
                  url: z.string().max(2000),
                  title: z.string().max(3000),
                  description: z.string().max(10000).optional(),
                }),
              )
              .max(20),
          })
          .optional(),
      })
      .parse(data);
    const results = (parsed.web?.results ?? [])
      .filter((r) => publicUrl(r.url))
      .map((r) => ({
        url: r.url,
        title: textOnly(r.title, 500),
        description: textOnly(r.description ?? "", 2000),
      }));
    return {
      ...base,
      results,
      receipt: {
        status: "ok",
        message: `Found ${results.length} public search results for review. None has been confirmed as belonging to you and no score was changed.`,
      },
    };
  } catch {
    return { ...base, receipt: failureReceipt() };
  }
}

export function applyFootprintResult(
  workspace: Workspace,
  assetId: string,
  result: FootprintResult,
  now?: string | Date,
): Workspace {
  const asset = workspace.assets.find((a) => a.id === assetId);
  if (!asset)
    throw new Error("Public-footprint results require a scoped asset.");
  const currentQuery = asset.kind === "identity" ? asset.label : asset.value;
  if (!currentQuery || result.query !== currentQuery.trim())
    throw new Error(
      "The public identifier changed while the search was running. Run a new search for the current asset.",
    );
  if (result.receipt.status !== "ok") return structuredClone(workspace);
  const time = isoNow(now),
    events: ThreatEvent[] = result.results.map((r) => ({
      id: `web:${stablePart(assetId)}:${stablePart(result.query)}:${stablePart(r.url)}`,
      source: "web",
      title: r.title,
      description: `Unconfirmed identity match. ${r.description}`.slice(
        0,
        2800,
      ),
      url: r.url,
      publishedAt: result.checkedAt,
      ingestedAt: time,
      relevance: "unassessed",
      assetId,
    }));
  return mergeEvents(workspace, events, time);
}
