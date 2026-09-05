import { describe, expect, test } from "bun:test";
import {
  addAsset,
  createSnapshot,
  createWorkspace,
  evaluateWorkspace,
  recordEvidence,
  removeAsset,
  updateAsset,
  WorkspaceSchema,
} from "./index";
import type { AssetPatch, Workspace } from "./types";
const NOW = "2026-09-04T12:00:00.000Z",
  LATER = "2026-09-04T12:00:01.000Z",
  AFTER = "2026-09-04T12:00:02.000Z";
function fixture() {
  let w = createWorkspace("Asset edit test", NOW);
  w = addAsset(
    w,
    {
      kind: "email",
      label: "Primary email",
      value: "owner@example.test",
      critical: true,
    },
    NOW,
  );
  w = addAsset(
    w,
    {
      kind: "email",
      label: "Recovery email",
      value: "recovery@example.test",
      critical: true,
    },
    NOW,
  );
  w = addAsset(
    w,
    {
      kind: "phone",
      label: "Recovery phone",
      value: "+12025550100",
      critical: true,
    },
    NOW,
  );
  return w;
}
function verify(w: Workspace, checkId: string, assetId: string) {
  return recordEvidence(
    w,
    {
      checkId,
      assetId,
      method: "guided",
      status: "pass",
      notes:
        "Inspected the official setting and verified the stated condition.",
    },
    NOW,
  );
}
function subject(w: Workspace, checkId: string, assetId: string, time = LATER) {
  return evaluateWorkspace(w, time)
    .checks.find((check) => check.checkId === checkId)!
    .subjects.find((s) => s.assetId === assetId)!;
}

describe("asset editing and evidence continuity", () => {
  test("label and critical changes preserve ID, evidence, score and immutable history", () => {
    let w = fixture();
    const asset = w.assets[0]!;
    w = verify(w, "accounts.sessions", asset.id);
    w = createSnapshot(w, NOW);
    const original = structuredClone(w),
      before = evaluateWorkspace(w, LATER);
    const updated = updateAsset(
      w,
      asset.id,
      { label: "Work email", critical: false },
      LATER,
    );
    expect(updated.assets[0]).toMatchObject({
      id: asset.id,
      kind: "email",
      label: "Work email",
      critical: false,
      value: asset.value,
    });
    expect(updated.evidence).toEqual(w.evidence);
    expect(updated.snapshots).toEqual(w.snapshots);
    expect(evaluateWorkspace(updated, LATER).score).toBe(before.score);
    expect(w).toEqual(original);
  });
  test("identifier changes reopen all existing checks on that asset without erasing observations or snapshots", () => {
    let w = fixture();
    const asset = w.assets[0]!,
      other = w.assets[1]!;
    w = verify(w, "accounts.sessions", asset.id);
    w = verify(w, "exposure.breach-review", asset.id);
    w = verify(w, "accounts.sessions", other.id);
    w = createSnapshot(w, NOW);
    const original = structuredClone(w.evidence);
    const updated = updateAsset(
      w,
      asset.id,
      { value: "replacement@example.test" },
      LATER,
    );
    expect(updated.evidence.slice(0, original.length)).toEqual(original);
    expect(updated.evidence.length).toBe(original.length + 2);
    expect(subject(updated, "accounts.sessions", asset.id)).toMatchObject({
      status: "unknown",
    });
    expect(subject(updated, "accounts.sessions", asset.id).reason).toContain(
      "identifier changed",
    );
    expect(subject(updated, "accounts.sessions", other.id).status).toBe("pass");
    expect(updated.snapshots).toEqual(w.snapshots);
    expect(WorkspaceSchema.safeParse(updated).success).toBe(true);
  });
  test("same-instant editing cannot retain a previous passing score; a later fresh check resolves invalidation", () => {
    let w = fixture();
    const asset = w.assets[0]!;
    w = verify(w, "accounts.sessions", asset.id);
    w = updateAsset(w, asset.id, { value: "replacement@example.test" }, NOW);
    expect(subject(w, "accounts.sessions", asset.id, NOW).status).toBe(
      "unknown",
    );
    w = recordEvidence(
      w,
      {
        checkId: "accounts.sessions",
        assetId: asset.id,
        status: "pass",
        method: "guided",
        notes:
          "Reverified the replacement account's current recognized sessions.",
      },
      AFTER,
    );
    expect(subject(w, "accounts.sessions", asset.id, AFTER).status).toBe(
      "pass",
    );
  });
  test("recovery route changes reopen recovery checks for the asset and transitively dependent accounts only", () => {
    let w = fixture();
    const primary = w.assets[0]!,
      recovery = w.assets[1]!,
      phone = w.assets[2]!;
    w.assets[0]!.recoveryAssetIds = [recovery.id];
    w = verify(w, "recovery.channels", primary.id);
    w = verify(w, "recovery.channels", recovery.id);
    w = verify(w, "accounts.sessions", primary.id);
    w = verify(w, "accounts.sessions", recovery.id);
    const updated = updateAsset(
      w,
      recovery.id,
      { recoveryAssetIds: [phone.id] },
      LATER,
    );
    expect(subject(updated, "recovery.channels", primary.id).status).toBe(
      "unknown",
    );
    expect(subject(updated, "recovery.channels", recovery.id).status).toBe(
      "unknown",
    );
    expect(subject(updated, "accounts.sessions", primary.id).status).toBe(
      "pass",
    );
    expect(subject(updated, "accounts.sessions", recovery.id).status).toBe(
      "pass",
    );
  });
  test("changing a dependency identifier reopens dependent recovery but preserves unrelated sign-in evidence", () => {
    let w = fixture();
    const primary = w.assets[0]!,
      recovery = w.assets[1]!;
    w.assets[0]!.recoveryAssetIds = [recovery.id];
    w = verify(w, "recovery.backup-access", primary.id);
    w = verify(w, "accounts.sessions", primary.id);
    const updated = updateAsset(
      w,
      recovery.id,
      { value: "other-recovery@example.test" },
      LATER,
    );
    expect(subject(updated, "recovery.backup-access", primary.id).status).toBe(
      "unknown",
    );
    expect(subject(updated, "accounts.sessions", primary.id).status).toBe(
      "pass",
    );
  });
  test("clearing a recovery identifier or deleting a recovery asset reopens affected controls", () => {
    let w = fixture();
    const primary = w.assets[0]!,
      recovery = w.assets[1]!;
    w.assets[0]!.recoveryAssetIds = [recovery.id];
    w = verify(w, "recovery.channels", primary.id);
    w = verify(w, "accounts.sessions", recovery.id);
    const cleared = updateAsset(w, recovery.id, { value: "" }, LATER);
    expect(cleared.assets[1]!.value).toBeUndefined();
    expect(subject(cleared, "accounts.sessions", recovery.id).status).toBe(
      "unknown",
    );
    const removed = removeAsset(w, recovery.id, LATER);
    expect(removed.assets[0]!.recoveryAssetIds).toEqual([]);
    expect(subject(removed, "recovery.channels", primary.id).status).toBe(
      "unknown",
    );
    expect(WorkspaceSchema.safeParse(removed).success).toBe(true);
  });
  test("equivalent email case and recovery-edge ordering changes do not erase earned verification", () => {
    let w = fixture();
    const primary = w.assets[0]!,
      recovery = w.assets[1]!,
      phone = w.assets[2]!;
    w.assets[0]!.recoveryAssetIds = [recovery.id, phone.id];
    w = verify(w, "recovery.channels", primary.id);
    const updated = updateAsset(
      w,
      primary.id,
      {
        value: "OWNER@EXAMPLE.TEST",
        recoveryAssetIds: [phone.id, recovery.id],
      },
      LATER,
    );
    expect(updated.evidence).toEqual(w.evidence);
    expect(subject(updated, "recovery.channels", primary.id).status).toBe(
      "pass",
    );
  });
  test("invalid patches reject immutable fields, duplicates, missing refs, secrets and invalid values without mutation", () => {
    const w = fixture(),
      asset = w.assets[0]!,
      original = structuredClone(w);
    for (const patch of [
      {},
      { kind: "phone" },
      { id: "new-id" },
      { label: " " },
      { value: "bad email" },
      { value: "recovery@example.test" },
      { label: "api_key=abcdefghijklmnop" },
      { recoveryAssetIds: ["missing"] },
      { recoveryAssetIds: [w.assets[1]!.id, w.assets[1]!.id] },
      { recoveryAssetIds: Array.from({ length: 101 }, (_, i) => `a${i}`) },
    ])
      expect(() =>
        updateAsset(w, asset.id, patch as AssetPatch, LATER),
      ).toThrow();
    expect(() =>
      updateAsset(w, "missing", { label: "Missing" }, LATER),
    ).toThrow("does not exist");
    expect(w).toEqual(original);
  });
  test("identity numbers remain prohibited and retained threat matches become historical on identifier changes", () => {
    let w = fixture();
    const asset = w.assets[0]!;
    w = addAsset(
      w,
      { kind: "identity", label: "Example Person", critical: false },
      NOW,
    );
    expect(() =>
      updateAsset(w, w.assets.at(-1)!.id, { value: "123456789" }, LATER),
    ).toThrow("identity-document");
    w.threatEvents.push({
      id: "historic-event",
      source: "hibp",
      title: "Synthetic breach",
      description: "Synthetic historic association",
      url: "https://example.test/breach",
      publishedAt: NOW,
      ingestedAt: NOW,
      relevance: "confirmed",
      assetId: asset.id,
    });
    const updated = updateAsset(
      w,
      asset.id,
      { value: "replacement@example.test" },
      LATER,
    );
    expect(updated.threatEvents[0]).toMatchObject({
      id: "historic-event",
      relevance: "unassessed",
    });
    expect(updated.threatEvents[0]!.description).toContain(
      "previous asset identifier",
    );
  });
  test("dense recovery graph removal deduplicates invalidations rather than enumerating paths", () => {
    let w = fixture();
    w.assets = w.assets.map((a) => ({
      ...a,
      recoveryAssetIds: w.assets
        .filter((other) => other.id !== a.id)
        .map((other) => other.id),
    }));
    for (const asset of w.assets.filter((a) => a.kind === "email"))
      w = verify(w, "recovery.channels", asset.id);
    const updated = removeAsset(w, w.assets[2]!.id, LATER);
    expect(updated.evidence.filter((e) => e.facts?.invalidation)).toHaveLength(
      2,
    );
    expect(WorkspaceSchema.safeParse(updated).success).toBe(true);
  });
});
