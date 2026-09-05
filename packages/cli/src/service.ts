import {
  CATEGORIES,
  CHECKS,
  CATALOG_VERSION,
  SCORE_VERSION,
  createWorkspace,
  evaluateWorkspace,
  recordEvidence,
  createSnapshot,
  addAsset,
  updateAsset,
  AssetPatchSchema,
  removeAsset,
  recordAction,
  mergeWorkspace,
  WorkspaceSchema,
  type Workspace,
  type EvidenceInput,
  type Asset,
  type RemediationAction,
} from "@palisade/core";
import { z } from "zod";
import { createHash } from "node:crypto";
import { LocalStore } from "./store";
import { PalisadeError } from "./errors";
import { collectMac } from "./collector";
import { RemoteService, type AuditService, type RequestMethod } from "./remote";
export { RemoteService, type AuditService } from "./remote";
const id = z.string().min(1).max(120);
const subject = { checkId: id, assetId: id.optional() };
const guidedSchema = z
  .object({
    ...subject,
    status: z.enum(["pass", "partial", "fail", "unknown", "not_applicable"]),
    notes: z.string().max(3000).optional(),
    facts: z
      .record(
        z.string(),
        z.union([
          z.string(),
          z.number().finite(),
          z.boolean(),
          z.null(),
          z.array(z.string()),
          z.array(z.number().finite()),
        ]),
      )
      .optional(),
    observedAt: z.iso.datetime({ offset: true }).optional(),
  })
  .strict();
const actionSchema = z
  .object({
    ...subject,
    status: z.enum(["planned", "completed"]),
    notes: z.string().max(3000).optional(),
  })
  .strict();
const assetSchema = z
  .object({
    kind: z.enum([
      "email",
      "phone",
      "device",
      "domain",
      "financial",
      "password_manager",
      "identity",
      "network",
    ]),
    label: z.string().trim().min(1).max(120),
    value: z.string().max(320).optional(),
    critical: z.boolean().default(false),
    recoveryAssetIds: z.array(id).max(30).optional(),
  })
  .strict();
const scanSchema = z.object({ assetId: id, consent: z.literal(true) }).strict();
// A deterministic 52-bit state fingerprint is a safe JSON integer and detects changes
// across CLI/MCP processes without wrapping the portable workspace in storage metadata.
function workspaceRevision(workspace: Workspace): number {
  return Number.parseInt(
    createHash("sha256")
      .update(JSON.stringify(WorkspaceSchema.parse(workspace)))
      .digest("hex")
      .slice(0, 13),
    16,
  );
}
function envelope(workspace: Workspace) {
  return {
    workspace,
    evaluation: evaluateWorkspace(workspace),
    revision: workspaceRevision(workspace),
  };
}

export interface LocalServiceOptions {
  fetch?: typeof fetch;
  env?: Partial<
    Pick<NodeJS.ProcessEnv, "HIBP_API_KEY" | "BRAVE_SEARCH_API_KEY">
  >;
  macCollector?: typeof collectMac;
}
export class LocalService implements AuditService {
  readonly store: LocalStore<Workspace>;
  constructor(
    dataDir?: string,
    private readonly options: LocalServiceOptions = {},
  ) {
    this.store = new LocalStore(dataDir, (value) =>
      WorkspaceSchema.parse(value),
    );
  }
  async init(name = "My security audit") {
    return envelope(
      await this.store.update((current) => {
        if (current)
          throw new PalisadeError(
            "ALREADY_INITIALIZED",
            "A workspace already exists. Export it or use another --data-dir to start a separate audit.",
            2,
          );
        return createWorkspace(name);
      }),
    );
  }
  private async workspace() {
    const current = await this.store.read();
    return (
      current ??
      this.store.update(
        (existing) => existing ?? createWorkspace("My security audit"),
      )
    );
  }
  async request(
    method: RequestMethod,
    path: string,
    body?: unknown,
  ): Promise<unknown> {
    if (method === "GET" && path === "/catalog")
      return {
        categories: CATEGORIES,
        checks: CHECKS,
        catalogVersion: CATALOG_VERSION,
        scoreVersion: SCORE_VERSION,
      };
    if (method === "GET" && path === "/workspace")
      return envelope(await this.workspace());
    if (method === "GET" && path === "/export") return this.workspace();
    if (method === "GET" && path === "/integrations")
      return {
        hibp: {
          configured: Boolean((this.options.env ?? process.env).HIBP_API_KEY),
        },
        brave: {
          configured: Boolean(
            (this.options.env ?? process.env).BRAVE_SEARCH_API_KEY,
          ),
        },
        publicFeeds: { available: true },
        monitoring: { enabled: false },
        emailVerification: { available: false },
        mode: "local",
        message:
          "Local scans run on demand. Set HIBP_API_KEY in the process environment; it is not persisted.",
      };
    if (method === "POST" && path === "/scans/mac") {
      const input = scanSchema.parse(body);
      const workspace = await this.workspace();
      const targetAsset = workspace.assets.find(
        (asset) => asset.id === input.assetId && asset.kind === "device",
      );
      if (!targetAsset)
        throw new PalisadeError(
          "INVALID_ASSET",
          "Choose an existing device asset for this Mac.",
          2,
        );
      const receipt = await (this.options.macCollector ?? collectMac)();
      if (receipt.status === "unavailable")
        return { ...envelope(workspace), receipt };
      const observedAt = new Date().toISOString();
      const updated = await this.store.update((current) => {
        let next = current ?? workspace;
        const currentTarget = next.assets.find(
          (asset) => asset.id === input.assetId,
        );
        if (!currentTarget || currentTarget.value !== targetAsset.value)
          throw new PalisadeError(
            "ASSET_CHANGED",
            "The device identifier changed while the collector was running. Re-run the scan for the current device.",
          );
        for (const observation of receipt.observations) {
          const checkId =
            observation.collector === "filevault"
              ? "devices.disk-encryption"
              : observation.collector === "firewall"
                ? "devices.firewall"
                : undefined;
          if (checkId) {
            const needsExceptionReview =
              observation.collector === "firewall" &&
              observation.status === "pass";
            next = recordEvidence(next, {
              checkId,
              assetId: input.assetId,
              status: needsExceptionReview ? "unknown" : observation.status,
              method: "local",
              observedAt,
              notes:
                observation.summary +
                (needsExceptionReview
                  ? " Review permitted inbound applications before marking this check passed."
                  : ""),
              facts: observation.facts,
            });
          }
        }
        return next;
      });
      return { ...envelope(updated), receipt };
    }
    if (
      method === "POST" &&
      (path === "/scans/hibp" ||
        path === "/scans/threats" ||
        path === "/scans/footprint")
    )
      return this.scan(path, body);
    const updated = await this.store.update((current) => {
      const workspace = current ?? createWorkspace("My security audit");
      if (method === "POST" && path === "/assets")
        return addAsset(
          workspace,
          assetSchema.parse(body) as Omit<Asset, "id">,
        );
      if (method === "PATCH" && path.startsWith("/assets/"))
        return updateAsset(
          workspace,
          id.parse(path.slice("/assets/".length)),
          AssetPatchSchema.parse(body),
        );
      if (method === "DELETE" && path.startsWith("/assets/"))
        return removeAsset(workspace, id.parse(path.slice("/assets/".length)));
      if (method === "POST" && path === "/evidence")
        return recordEvidence(workspace, {
          ...guidedSchema.parse(body),
          method: "guided",
        } as EvidenceInput);
      if (method === "POST" && path === "/actions")
        return recordAction(
          workspace,
          actionSchema.parse(body) as Pick<
            RemediationAction,
            "checkId" | "assetId" | "status" | "notes"
          >,
        );
      if (method === "DELETE" && path.startsWith("/audits/")) {
        z.object({ confirmation: z.literal("DELETE") })
          .strict()
          .parse(body);
        const snapshotId = id.parse(path.slice("/audits/".length));
        if (!workspace.snapshots.some((snapshot) => snapshot.id === snapshotId))
          throw new PalisadeError(
            "NOT_FOUND",
            "The audit snapshot does not exist.",
            2,
          );
        return {
          ...workspace,
          snapshots: workspace.snapshots.filter(
            (snapshot) => snapshot.id !== snapshotId,
          ),
          updatedAt: new Date().toISOString(),
        };
      }
      if (method === "POST" && path === "/audits") {
        z.object({})
          .strict()
          .parse(body ?? {});
        return createSnapshot(workspace);
      }
      if (method === "POST" && path === "/imports")
        return mergeWorkspace(
          workspace,
          z.object({ workspace: z.unknown() }).strict().parse(body).workspace,
        );
      if (method === "PATCH" && path === "/workspace") {
        const input = z
          .object({
            name: z.string().trim().min(1).max(120).optional(),
            settings: z
              .object({
                region: z.string().max(20).optional(),
                modules: z.array(z.string().max(30)).max(20).optional(),
                monitoring: z.boolean().optional(),
              })
              .strict()
              .optional(),
            revision: z.number().int().nonnegative(),
          })
          .strict()
          .parse(body);
        if (input.revision !== workspaceRevision(workspace))
          throw new PalisadeError(
            "REVISION_CONFLICT",
            "The workspace changed since you read it. Read the latest workspace and retry your preference update.",
            2,
          );
        if (input.settings?.monitoring)
          throw new PalisadeError(
            "UNAVAILABLE",
            "Local mode runs on demand. Configure hosted monitoring in the web platform.",
            2,
          );
        return WorkspaceSchema.parse({
          ...workspace,
          ...(input.name ? { name: input.name } : {}),
          settings: { ...workspace.settings, ...input.settings },
          updatedAt: new Date().toISOString(),
        });
      }
      throw new PalisadeError(
        "UNKNOWN_OPERATION",
        `Unsupported operation: ${method} ${path}`,
        2,
      );
    });
    return envelope(updated);
  }
  private async scan(path: string, body: unknown): Promise<unknown> {
    // Implemented through the same provider adapters as the hosted service.
    if (path === "/scans/footprint") {
      const input = scanSchema.parse(body);
      const workspace = await this.workspace();
      const asset = workspace.assets.find(
        (asset) => asset.id === input.assetId,
      );
      const query =
        asset?.value ?? (asset?.kind === "identity" ? asset.label : undefined);
      if (!query)
        throw new PalisadeError(
          "INVALID_ASSET",
          "Choose an identity asset with a public name label, or an owned public-identifier asset with a value to search.",
          2,
        );
      const { searchFootprint, applyFootprintResult } =
        await import("@palisade/core");
      const result = await searchFootprint(
        query,
        (this.options.env ?? process.env).BRAVE_SEARCH_API_KEY ?? "",
        { consent: true, fetch: this.options.fetch },
      );
      if (result.receipt.status !== "ok")
        return { ...envelope(workspace), receipt: result.receipt };
      const updated = await this.store.update((current) =>
        applyFootprintResult(current ?? workspace, asset!.id, result),
      );
      return { ...envelope(updated), receipt: result.receipt };
    }
    if (path === "/scans/hibp") {
      const input = scanSchema.parse(body);
      const workspace = await this.workspace();
      const asset = workspace.assets.find(
        (asset) => asset.id === input.assetId,
      );
      if (!asset || asset.kind !== "email" || !asset.value)
        throw new PalisadeError(
          "INVALID_ASSET",
          "Choose an email asset with an email address.",
          2,
        );
      const { checkHibp, applyHibpResult } = await import("@palisade/core");
      const result = await checkHibp(
        asset.value,
        (this.options.env ?? process.env).HIBP_API_KEY ?? "",
        { consent: true, ownershipVerified: true, fetch: this.options.fetch },
      );
      const updated = await this.store.update((current) =>
        applyHibpResult(current ?? workspace, asset.id, result),
      );
      return { ...envelope(updated), receipt: result.receipt };
    }
    z.object({})
      .strict()
      .parse(body ?? {});
    const { fetchThreatFeeds, applyThreatFeedResult } =
      await import("@palisade/core");
    const result = await fetchThreatFeeds({ fetch: this.options.fetch });
    const workspace = await this.workspace();
    if (!result.events.length)
      return { ...envelope(workspace), receipt: result.receipt };
    const updated = await this.store.update((current) =>
      applyThreatFeedResult(current ?? workspace, result),
    );
    return { ...envelope(updated), receipt: result.receipt };
  }
}
export function createService(
  options: { host?: string; token?: string; dataDir?: string } = {},
): AuditService {
  return options.host
    ? new RemoteService(options.host, options.token)
    : new LocalService(options.dataDir);
}
