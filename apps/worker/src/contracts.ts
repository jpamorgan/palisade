import { z } from "zod";
import {
  AssetInputSchema,
  AssetPatchSchema,
  SettingsSchema,
} from "@palisade/core";

/** Shared request contracts are used by handlers and the generated OpenAPI document. */
export const ApiBodies = {
  updateWorkspace: z
    .object({
      name: z.string().trim().min(1).max(100).optional(),
      settings: SettingsSchema.partial().optional(),
      revision: z.number().int().positive(),
    })
    .strict(),
  addAsset: AssetInputSchema,
  updateAsset: AssetPatchSchema,
  recordEvidence: z
    .object({
      checkId: z.string().max(100),
      assetId: z.string().max(100).optional(),
      status: z.enum(["pass", "partial", "fail", "unknown", "not_applicable"]),
      notes: z.string().max(2000).optional(),
      facts: z
        .record(
          z.string(),
          z.union([
            z.string().max(500),
            z.number().finite(),
            z.boolean(),
            z.null(),
            z.array(z.string().max(500)).max(30),
            z.array(z.number().finite()).max(30),
          ]),
        )
        .optional(),
      observedAt: z.iso.datetime().optional(),
    })
    .strict(),
  recordAction: z
    .object({
      checkId: z.string().max(100),
      assetId: z.string().max(100).optional(),
      status: z.enum(["planned", "completed"]),
      notes: z.string().max(2000).optional(),
    })
    .strict(),
  createAudit: z
    .object({ checkIds: z.array(z.string()).max(100).optional() })
    .strict(),
  delete: z.object({ confirmation: z.literal("DELETE") }).strict(),
  importWorkspace: z.object({ workspace: z.unknown() }).strict(),
  connectProvider: z
    .object({ apiKey: z.string().trim().min(10).max(256) })
    .strict(),
  scanAsset: z
    .object({ assetId: z.string(), consent: z.literal(true) })
    .strict(),
  createToken: z
    .object({
      name: z.string().trim().min(1).max(80),
      scopes: z
        .array(z.enum(["read", "write", "scan"]))
        .min(1)
        .max(3),
      expiresInDays: z.number().int().min(1).max(90).default(30),
    })
    .strict(),
  assistant: z
    .object({
      message: z.string().trim().min(1).max(1200),
      checkId: z.string().optional(),
    })
    .strict(),
};
