import { z } from "zod";
import {
  ActionInputSchema,
  AssetInputSchema,
  AssetPatchSchema,
  EvidenceInputSchema,
  FactsSchema,
} from "@palisade/core";

const text = (maximum: number) =>
  z
    .string()
    .trim()
    .min(1)
    .max(maximum)
    .refine(
      (value) => FactsSchema.safeParse({ text: value }).success,
      "Use a concise description without passwords, tokens, recovery codes or other secrets.",
    );
export const PublicSourceUrl = z
  .url()
  .max(2000)
  .refine((value) => {
    const url = new URL(value);
    return url.protocol === "https:" && !url.username && !url.password;
  }, "Use a public HTTPS URL without credentials.");
const WriteFields = {
  revision: z.number().int().positive(),
  operationId: z.uuid(),
};
const Empty = z.object({}).strict();
const Write = z.object(WriteFields).strict();
export const ScanInputs = {
  empty: Empty,
  begin: Write,
  asset: AssetInputSchema.safeExtend(WriteFields),
  updateAsset: z
    .object({
      ...WriteFields,
      assetId: z.string().min(1).max(160),
      patch: AssetPatchSchema,
    })
    .strict(),
  evidence: EvidenceInputSchema.omit({ method: true, notes: true })
    .extend({
      ...WriteFields,
      notes: text(1000).min(12),
      source: z
        .object({
          kind: z.enum([
            "user_confirmation",
            "local_observation",
            "public_source",
          ]),
          label: text(160),
          url: PublicSourceUrl.optional(),
        })
        .strict(),
    })
    .strict(),
  action: ActionInputSchema.extend(WriteFields),
  progress: z
    .object({
      ...WriteFields,
      status: z.enum(["running", "waiting_for_user", "blocked"]),
      phase: text(80),
      message: text(400),
    })
    .strict(),
  context: z
    .object({
      ...WriteFields,
      title: text(300),
      description: text(1000),
      url: PublicSourceUrl,
      publishedAt: z.iso.datetime(),
    })
    .strict(),
  complete: z.object({ ...WriteFields, summary: text(600) }).strict(),
  delete: z.object({ confirmation: z.literal("DELETE") }).strict(),
};
