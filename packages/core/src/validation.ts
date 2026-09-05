import { z } from "zod";
import { CHECK_BY_ID } from "./catalog";
import type { Workspace } from "./types";

const Id = z
  .string()
  .min(1)
  .max(160)
  .regex(
    /^[a-zA-Z0-9._:-]+$/,
    "Use a stable identifier without spaces or URL syntax.",
  );
const Timestamp = z
  .string()
  .datetime({ offset: true })
  .refine((s) => Number.isFinite(Date.parse(s)), "Invalid timestamp");
const secretPattern =
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\b(?:sk_live_|sk-proj-|ghp_|github_pat_|AKIA)[A-Za-z0-9_-]{12,}|\b(?:password|api[_ -]?key|access[_ -]?token|secret|seed[_ -]?phrase|recovery[_ -]?code)\s*[:=]\s*\S{4,}/i;
const SafeText = (max: number) =>
  z
    .string()
    .max(max)
    .refine(
      (value) => !secretPattern.test(value),
      "Do not include passwords, tokens, private keys, recovery codes or other raw secrets.",
    );
const factValue = z.union([
  SafeText(1000),
  z.number().finite(),
  z.boolean(),
  z.null(),
  z.array(SafeText(300)).max(100),
  z.array(z.number().finite()).max(100),
]);
export const FactsSchema = z
  .record(z.string().min(1).max(80), factValue)
  .refine((facts) => Object.keys(facts).length <= 40, "Too many facts")
  .superRefine((facts, ctx) => {
    for (const key of Object.keys(facts))
      if (
        /^(?:__proto__|constructor|prototype|password|passphrase|secret|token|api[_-]?key|private[_-]?key|recovery[_-]?code|seed[_-]?phrase|cookie|authorization)$/i.test(
          key,
        )
      )
        ctx.addIssue({
          code: "custom",
          message: `Fact key '${key}' may contain secrets or unsafe properties.`,
          path: [key],
        });
  });
export const AssetKindSchema = z.enum([
  "email",
  "phone",
  "device",
  "domain",
  "financial",
  "password_manager",
  "identity",
  "network",
]);
export const EvidenceStatusSchema = z.enum([
  "pass",
  "partial",
  "fail",
  "unknown",
  "not_applicable",
]);
export const EvidenceMethodSchema = z.enum([
  "guided",
  "local",
  "provider",
  "import",
]);
const checkId = Id.refine(
  (id) => CHECK_BY_ID.has(id),
  "Unknown check identifier",
);
export const AssetInputSchema = z
  .object({
    kind: AssetKindSchema,
    label: SafeText(120).min(1),
    value: SafeText(320).optional(),
    critical: z.boolean(),
    recoveryAssetIds: z.array(Id).max(100).optional(),
  })
  .strict()
  .superRefine((asset, ctx) => {
    if (
      asset.kind === "email" &&
      asset.value !== undefined &&
      !z.email().safeParse(asset.value).success
    )
      ctx.addIssue({
        code: "custom",
        message: "Enter a valid email address.",
        path: ["value"],
      });
    if (asset.kind === "identity" && asset.value)
      ctx.addIssue({
        code: "custom",
        message:
          "Keep identity-document numbers out of the audit. Use a descriptive label only.",
        path: ["value"],
      });
  });
export const AssetSchema = AssetInputSchema.safeExtend({ id: Id });
export const AssetPatchSchema = z
  .object({
    label: SafeText(120).trim().min(1).optional(),
    value: SafeText(320).optional(),
    critical: z.boolean().optional(),
    recoveryAssetIds: z
      .array(Id)
      .max(100)
      .refine(
        (refs) => new Set(refs).size === refs.length,
        "Recovery assets must be unique.",
      )
      .optional(),
  })
  .strict()
  .refine(
    (patch) => Object.values(patch).some((value) => value !== undefined),
    "Provide at least one asset field to update.",
  );
export const EvidenceInputSchema = z
  .object({
    checkId,
    assetId: Id.optional(),
    status: EvidenceStatusSchema,
    method: EvidenceMethodSchema,
    observedAt: Timestamp.optional(),
    notes: SafeText(3000).optional(),
    facts: FactsSchema.optional(),
  })
  .strict();
export const EvidenceSchema = EvidenceInputSchema.extend({
  id: Id,
  observedAt: Timestamp,
});
export const ActionInputSchema = z
  .object({
    checkId,
    assetId: Id.optional(),
    status: z.enum(["planned", "completed"]),
    notes: SafeText(3000).optional(),
  })
  .strict();
export const RemediationActionSchema = ActionInputSchema.extend({
  id: Id,
  createdAt: Timestamp,
  updatedAt: Timestamp,
});
export const SettingsSchema = z
  .object({
    region: z.string().min(2).max(30),
    modules: z
      .array(z.enum(["developer", "public_figure", "crypto", "household"]))
      .max(4),
    monitoring: z.boolean(),
  })
  .strict();
const checkStatus = z.enum([
  "pass",
  "partial",
  "fail",
  "unknown",
  "not_applicable",
  "stale",
  "conflict",
  "imported",
]);
const SubjectResultSchema = z
  .object({
    assetId: Id.optional(),
    status: checkStatus,
    evidenceId: Id.optional(),
    reason: z.string().max(3000),
  })
  .strict();
const CheckResultSchema = SubjectResultSchema.extend({
  checkId,
  earnedPoints: z.number().finite().nonnegative(),
  maxPoints: z.number().finite().nonnegative(),
  assessed: z.boolean(),
  subjects: z.array(SubjectResultSchema).max(200),
});
const CategoryIdSchema = z.enum([
  "exposure",
  "accounts",
  "recovery",
  "devices",
  "network",
  "finance",
  "data",
  "response",
]);
const SeveritySchema = z.enum(["critical", "high", "medium", "low"]);
export const EvaluationSchema = z
  .object({
    score: z.number().int().min(0).max(100).nullable(),
    coverage: z.number().int().min(0).max(100),
    categories: z
      .array(
        z
          .object({
            categoryId: CategoryIdSchema,
            score: z.number().int().min(0).max(100).nullable(),
            coverage: z.number().int().min(0).max(100),
            earnedPoints: z.number().finite().nonnegative(),
            maxPoints: z.number().finite().nonnegative(),
            assessedPoints: z.number().finite().nonnegative(),
            checkCount: z.number().int().nonnegative(),
          })
          .strict(),
      )
      .max(8),
    checks: z.array(CheckResultSchema).max(200),
    findings: z
      .array(
        z
          .object({
            id: Id,
            checkId,
            assetId: Id.optional(),
            severity: SeveritySchema,
            title: z.string().max(500),
            description: z.string().max(3000),
            kind: z.enum(["gap", "verification", "dependency"]),
            action: z.string().max(3000),
          })
          .strict(),
      )
      .max(10000),
    evaluatedAt: Timestamp,
    catalogVersion: z.string().max(50),
    scoreVersion: z.string().max(50),
  })
  .strict();
export const AuditSnapshotSchema = z
  .object({
    id: Id,
    createdAt: Timestamp,
    evaluation: EvaluationSchema,
    assetIds: z.array(Id).max(200),
    evidenceIds: z.array(Id).max(10000),
    workspaceName: SafeText(120),
    settings: SettingsSchema,
  })
  .strict();
export const ThreatEventSchema = z
  .object({
    id: Id,
    source: z.enum(["hibp", "cisa", "rss", "web"]),
    title: SafeText(500),
    description: SafeText(3000),
    url: z
      .url()
      .max(2000)
      .refine(
        (v) => new URL(v).protocol === "https:",
        "Threat sources must use HTTPS",
      ),
    publishedAt: Timestamp,
    ingestedAt: Timestamp,
    relevance: z.enum(["unassessed", "potential", "confirmed"]),
    assetId: Id.optional(),
    identifiers: z.array(SafeText(200)).max(100).optional(),
  })
  .strict();
export const WorkspaceSchema = z
  .object({
    schemaVersion: z.literal(1),
    id: Id,
    name: SafeText(120).min(1),
    createdAt: Timestamp,
    updatedAt: Timestamp,
    assets: z.array(AssetSchema).max(200),
    evidence: z.array(EvidenceSchema).max(10000),
    actions: z.array(RemediationActionSchema).max(5000),
    snapshots: z.array(AuditSnapshotSchema).max(100),
    threatEvents: z.array(ThreatEventSchema).max(2000),
    settings: SettingsSchema,
  })
  .strict()
  .superRefine((workspace, ctx) => {
    for (const field of [
      "assets",
      "evidence",
      "actions",
      "snapshots",
      "threatEvents",
    ] as const) {
      const ids = new Set<string>();
      workspace[field].forEach((item, index) => {
        if (ids.has(item.id))
          ctx.addIssue({
            code: "custom",
            message: "Duplicate record identifier",
            path: [field, index, "id"],
          });
        ids.add(item.id);
      });
    }
    const assets = new Map(workspace.assets.map((a) => [a.id, a]));
    workspace.assets.forEach((asset, index) =>
      asset.recoveryAssetIds?.forEach((id) => {
        if (!assets.has(id))
          ctx.addIssue({
            code: "custom",
            message: "Recovery asset does not exist",
            path: ["assets", index, "recoveryAssetIds"],
          });
      }),
    );
    for (const field of ["evidence", "actions"] as const)
      workspace[field].forEach((item, index) => {
        const definition = CHECK_BY_ID.get(item.checkId);
        if (item.assetId && !assets.has(item.assetId))
          ctx.addIssue({
            code: "custom",
            message: "Referenced asset does not exist",
            path: [field, index, "assetId"],
          });
        if (
          item.assetId &&
          assets.has(item.assetId) &&
          definition?.assetKinds &&
          !definition.assetKinds.includes(assets.get(item.assetId)!.kind)
        )
          ctx.addIssue({
            code: "custom",
            message: "Asset kind does not match this check",
            path: [field, index, "assetId"],
          });
        if (item.assetId && !definition?.assetKinds)
          ctx.addIssue({
            code: "custom",
            message: "This check is workspace-wide",
            path: [field, index, "assetId"],
          });
      });
    if (Date.parse(workspace.updatedAt) < Date.parse(workspace.createdAt))
      ctx.addIssue({
        code: "custom",
        message: "Workspace update precedes creation",
        path: ["updatedAt"],
      });
  });
export const workspaceSchema = WorkspaceSchema;

/** Validate shape without granting proof. Imported observations stay historical until rechecked. */
export function validateImport(input: unknown): Workspace {
  let size: number;
  try {
    size = JSON.stringify(input).length;
  } catch {
    throw new Error("Import must be JSON-serializable.");
  }
  if (size > 5_000_000) throw new Error("Import exceeds the 5 MB limit.");
  const parsed = WorkspaceSchema.parse(input);
  return {
    ...parsed,
    evidence: parsed.evidence.map((e) => ({ ...e, method: "import" as const })),
    snapshots: [],
    threatEvents: parsed.threatEvents.map((e) => ({
      ...e,
      relevance: "unassessed" as const,
    })),
  };
}
