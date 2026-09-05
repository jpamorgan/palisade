import { describe, expect, test } from "bun:test";
import {
  CHECKS,
  CATEGORIES,
  WorkspaceSchema,
  createWorkspace,
  addAsset,
  recordEvidence,
  evaluateWorkspace,
  createSnapshot,
  recordAction,
  removeAsset,
  validateImport,
  mergeWorkspace,
  analyzeDependencies,
} from "./index";
import type { AssetKind, EvidenceStatus, Workspace } from "./types";

const NOW = "2026-09-04T12:00:00.000Z";
const LATER = "2026-09-04T12:00:01.000Z";
const NOTES =
  "Inspected the official settings and verified this control's documented condition.";
function fixture() {
  let workspace = createWorkspace("Example audit", NOW);
  for (const kind of [
    "email",
    "phone",
    "device",
    "domain",
    "financial",
    "password_manager",
    "identity",
    "network",
  ] as AssetKind[])
    workspace = addAsset(
      workspace,
      {
        kind,
        label: `Example ${kind}`,
        critical: true,
        ...(kind === "email" ? { value: "owner@example.test" } : {}),
      },
      NOW,
    );
  return workspace;
}
function attest(
  workspace: Workspace,
  checkId: string,
  status: EvidenceStatus = "pass",
  assetId?: string,
  time = NOW,
) {
  return recordEvidence(
    workspace,
    { checkId, status, assetId, method: "guided", notes: NOTES },
    time,
  );
}
function allPass() {
  let w = fixture();
  for (const check of CHECKS) {
    const assets = check.assetKinds
      ? w.assets.filter((a) => check.assetKinds!.includes(a.kind))
      : [];
    for (const assetId of assets.length ? assets.map((a) => a.id) : [undefined])
      w = attest(w, check.id, "pass", assetId);
  }
  return w;
}
const result = (w: Workspace, id: string, time = NOW) =>
  evaluateWorkspace(w, time).checks.find((c) => c.checkId === id)!;

describe("catalog and deterministic scoring", () => {
  test("at least 32 atomic checks have meaningful instructions and category weights total 100", () => {
    expect(CHECKS.length).toBeGreaterThanOrEqual(32);
    expect(new Set(CHECKS.map((c) => c.id)).size).toBe(CHECKS.length);
    expect(CATEGORIES.reduce((s, c) => s + c.weight, 0)).toBe(100);
    for (const c of CHECKS) {
      expect(c.verification.length).toBeGreaterThan(60);
      expect(c.remediation.steps.length).toBeGreaterThanOrEqual(3);
      expect(c.weight).toBeGreaterThan(0);
    }
  });
  test("fresh workspace has no fabricated score or coverage", () => {
    const evaluation = evaluateWorkspace(createWorkspace("Empty", NOW), NOW);
    expect(evaluation.score).toBeNull();
    expect(evaluation.coverage).toBe(0);
    expect(evaluation.checks.every((c) => c.status === "unknown")).toBe(true);
  });
  test("complete evidence yields 100/100 and exact replay is deterministic", () => {
    const workspace = allPass(),
      first = evaluateWorkspace(workspace, NOW);
    expect(first.score).toBe(100);
    expect(first.coverage).toBe(100);
    expect(
      evaluateWorkspace(JSON.parse(JSON.stringify(workspace)), NOW),
    ).toEqual(first);
    expect(
      WorkspaceSchema.safeParse(createSnapshot(workspace, NOW)).success,
    ).toBe(true);
  });
  test("known failures count as assessed but earn no points", () => {
    let w = allPass();
    w = attest(w, "response.rehearsal", "fail", undefined, LATER);
    const evaluation = evaluateWorkspace(w, LATER);
    expect(evaluation.coverage).toBe(100);
    expect(evaluation.score).toBe(99);
    expect(result(w, "response.rehearsal", LATER).earnedPoints).toBe(0);
  });
  test("one failed critical account is not diluted by extra healthy accounts", () => {
    let w = allPass();
    const email = w.assets.find((a) => a.kind === "email")!;
    w = attest(w, "accounts.phishing-resistant-mfa", "fail", email.id, LATER);
    const before = result(w, "accounts.phishing-resistant-mfa", LATER);
    w = addAsset(
      w,
      {
        kind: "email",
        label: "Minor account",
        value: "minor@example.test",
        critical: false,
      },
      LATER,
    );
    w = attest(
      w,
      "accounts.phishing-resistant-mfa",
      "pass",
      w.assets.at(-1)!.id,
      LATER,
    );
    const after = result(w, "accounts.phishing-resistant-mfa", LATER);
    expect(after.earnedPoints).toBe(0);
    expect(after.status).toBe("fail");
    expect(after.maxPoints).toBe(before.maxPoints);
    expect(after.subjects.at(-1)!.status).toBe("pass");
  });
  test("adding a healthy critical asset cannot hide a known noncritical gap", () => {
    let w = addAsset(
      createWorkspace("Scope", NOW),
      { kind: "device", label: "Existing laptop", critical: false },
      NOW,
    );
    const existing = w.assets[0]!;
    w = attest(w, "devices.disk-encryption", "fail", existing.id);
    w = addAsset(
      w,
      { kind: "device", label: "Primary laptop", critical: true },
      NOW,
    );
    w = attest(w, "devices.disk-encryption", "pass", w.assets.at(-1)!.id);
    const evaluation = evaluateWorkspace(w, NOW),
      check = evaluation.checks.find(
        (c) => c.checkId === "devices.disk-encryption",
      )!;
    expect(check.subjects.find((s) => s.assetId === existing.id)).toMatchObject(
      { status: "fail" },
    );
    expect(check.status).toBe("fail");
    expect(check.earnedPoints).toBe(0);
    expect(
      evaluation.findings.some(
        (f) =>
          f.checkId === "devices.disk-encryption" &&
          f.assetId === existing.id &&
          f.kind === "gap",
      ),
    ).toBe(true);
  });
  test("adding a critical account reopens aggregate coverage until its scope is verified", () => {
    let w = allPass();
    w = addAsset(
      w,
      {
        kind: "email",
        label: "New root",
        value: "root@example.test",
        critical: true,
      },
      NOW,
    );
    const r = result(w, "accounts.phishing-resistant-mfa");
    expect(r.status).toBe("unknown");
    expect(r.assessed).toBe(false);
    expect(r.earnedPoints).toBe(0);
    expect(r.subjects.some((s) => s.status === "pass")).toBe(true);
  });
  test("defined partial condition earns half control points", () => {
    let w = fixture();
    const email = w.assets.find((a) => a.kind === "email")!;
    for (const a of w.assets.filter((a) =>
      ["email", "financial", "password_manager", "domain"].includes(a.kind),
    ))
      w = attest(
        w,
        "accounts.phishing-resistant-mfa",
        a.id === email.id ? "partial" : "pass",
        a.id,
      );
    const r = result(w, "accounts.phishing-resistant-mfa");
    expect(r.status).toBe("partial");
    expect(r.earnedPoints).toBe(r.maxPoints / 2);
    expect(() => attest(w, "accounts.sessions", "partial", email.id)).toThrow(
      "partial-credit",
    );
  });
  test("non-applicability redistributes only within the affected area", () => {
    let w = allPass();
    w = attest(w, "response.rehearsal", "not_applicable", undefined, LATER);
    const e = evaluateWorkspace(w, LATER);
    expect(e.score).toBe(100);
    expect(result(w, "response.rehearsal", LATER).maxPoints).toBe(0);
    expect(result(w, "response.incident-plan", LATER).maxPoints).toBeCloseTo(
      5 / 3,
      10,
    );
    expect(result(w, "exposure.public-identifiers", LATER).maxPoints).toBe(2);
  });
  test("an entirely non-applicable area redistributes across other areas", () => {
    let w = allPass();
    for (const check of CHECKS.filter((c) => c.categoryId === "response")) {
      for (const subject of result(w, check.id).subjects)
        w = attest(w, check.id, "not_applicable", subject.assetId, LATER);
    }
    const e = evaluateWorkspace(w, LATER);
    expect(e.score).toBe(100);
    expect(e.coverage).toBe(100);
    expect(
      e.categories.find((c) => c.categoryId === "response")!.maxPoints,
    ).toBe(0);
  });
  test("all controls non-applicable yields no score", () => {
    let w = createWorkspace("No applicable scope", NOW);
    for (const c of CHECKS) w = attest(w, c.id, "not_applicable");
    expect(evaluateWorkspace(w, NOW).score).toBeNull();
    expect(evaluateWorkspace(w, NOW).coverage).toBe(0);
  });
});

describe("evidence lifecycle and provenance", () => {
  test("freshness boundary is inclusive; beyond boundary is stale with zero assessed points", () => {
    const w = attest(createWorkspace("Freshness", NOW), "response.rehearsal");
    const boundary = new Date(Date.parse(NOW) + 180 * 86400000).toISOString();
    expect(result(w, "response.rehearsal", boundary).status).toBe("pass");
    expect(
      result(
        w,
        "response.rehearsal",
        new Date(Date.parse(boundary) + 1).toISOString(),
      ).status,
    ).toBe("stale");
  });
  test("future evidence is rejected and never counts during historical evaluation", () => {
    const w = createWorkspace("Time", NOW);
    expect(() =>
      recordEvidence(
        w,
        {
          checkId: "response.rehearsal",
          status: "pass",
          method: "guided",
          notes: NOTES,
          observedAt: LATER,
        },
        NOW,
      ),
    ).toThrow("future");
    const future = attest(w, "response.rehearsal", "pass", undefined, LATER);
    expect(result(future, "response.rehearsal", NOW).status).toBe("unknown");
  });
  test("same-time disagreement is conflict regardless of ordering; newer verification resolves it", () => {
    let w = attest(createWorkspace("Conflict", NOW), "response.rehearsal");
    w = attest(w, "response.rehearsal", "fail");
    expect(result(w, "response.rehearsal").status).toBe("conflict");
    expect(
      result(
        { ...w, evidence: [...w.evidence].reverse() },
        "response.rehearsal",
      ),
    ).toEqual(result(w, "response.rehearsal"));
    w = attest(w, "response.rehearsal", "pass", undefined, LATER);
    expect(result(w, "response.rehearsal", LATER).status).toBe("pass");
  });
  test("equivalent offset timestamps conflict rather than allowing timestamp formatting bypass", () => {
    let w = attest(createWorkspace("Offsets", NOW), "response.rehearsal");
    w = recordEvidence(
      w,
      {
        checkId: "response.rehearsal",
        method: "guided",
        status: "fail",
        observedAt: "2026-09-04T08:00:00-04:00",
        notes: NOTES,
      },
      NOW,
    );
    expect(result(w, "response.rehearsal").status).toBe("conflict");
  });
  test("action completion changes no evidence, score or coverage", () => {
    const w = createWorkspace("Action", NOW),
      updated = recordAction(
        w,
        {
          checkId: "response.rehearsal",
          status: "completed",
          notes: "Completed the guided step.",
        },
        NOW,
      );
    expect(updated.evidence).toEqual([]);
    expect(evaluateWorkspace(updated, NOW)).toEqual(evaluateWorkspace(w, NOW));
  });
  test("bare done, secrets, unsupported provider evidence and mismatched assets are rejected", () => {
    const w = fixture(),
      email = w.assets.find((a) => a.kind === "email")!;
    expect(() =>
      recordEvidence(
        w,
        {
          checkId: "response.rehearsal",
          status: "pass",
          method: "guided",
          notes: "Done",
        },
        NOW,
      ),
    ).toThrow();
    expect(() =>
      recordEvidence(
        w,
        {
          checkId: "response.rehearsal",
          status: "pass",
          method: "guided",
          notes: "password=super-secret-value",
        },
        NOW,
      ),
    ).toThrow();
    expect(() =>
      recordEvidence(
        w,
        {
          checkId: "response.rehearsal",
          status: "pass",
          method: "provider",
          notes: NOTES,
        },
        NOW,
      ),
    ).toThrow("method");
    expect(() => attest(w, "devices.firewall", "pass", email.id)).toThrow(
      "match",
    );
    expect(() => attest(w, "devices.firewall")).toThrow("Choose");
  });
  test("raw identity identifiers and secret fact keys are rejected", () => {
    const w = createWorkspace("No secrets", NOW);
    expect(() =>
      addAsset(
        w,
        { kind: "identity", label: "ID", value: "123-45-6789", critical: true },
        NOW,
      ),
    ).toThrow("identity-document");
    expect(() =>
      recordEvidence(
        w,
        {
          checkId: "response.rehearsal",
          status: "unknown",
          method: "guided",
          facts: { apiKey: "whatever" },
        },
        NOW,
      ),
    ).toThrow();
  });
  test("snapshot and subsequent mutations do not mutate previous workspace or snapshot", () => {
    const w = attest(createWorkspace("Immutable", NOW), "response.rehearsal"),
      snap = createSnapshot(w, NOW);
    const saved = JSON.stringify(snap.snapshots[0]);
    const next = attest(snap, "response.rehearsal", "fail", undefined, LATER);
    expect(w.snapshots).toEqual([]);
    expect(JSON.stringify(next.snapshots[0])).toBe(saved);
    next.snapshots[0]!.settings.region = "CA";
    expect(snap.snapshots[0]!.settings.region).toBe("unspecified");
  });
  test("deleting an asset retains snapshots while reopening asset scope", () => {
    let w = allPass();
    w = createSnapshot(w, NOW);
    const device = w.assets.find((a) => a.kind === "device")!;
    w = removeAsset(w, device.id, LATER);
    expect(w.snapshots[0]!.assetIds).toContain(device.id);
    expect(w.evidence.some((e) => e.assetId === device.id)).toBe(false);
    expect(result(w, "devices.disk-encryption", LATER).status).toBe("unknown");
    expect(WorkspaceSchema.safeParse(w).success).toBe(true);
  });
});

describe("imports and recovery graphs", () => {
  test("imports cannot forge proof or scores and preserve original observations as historical", () => {
    const source = createSnapshot(allPass(), NOW),
      imported = validateImport(source);
    expect(imported.snapshots).toEqual([]);
    expect(imported.evidence.every((e) => e.method === "import")).toBe(true);
    expect(evaluateWorkspace(imported, NOW).score).toBeNull();
    expect(result(imported, "response.rehearsal").status).toBe("imported");
    expect(source.evidence.every((e) => e.method === "guided")).toBe(true);
  });
  test("safe merge is idempotent and does not overwrite fresh trusted evidence", () => {
    const target = attest(
        createWorkspace("Target", NOW),
        "response.rehearsal",
        "fail",
      ),
      source = attest(
        createWorkspace("Source", NOW),
        "response.rehearsal",
        "pass",
        undefined,
        LATER,
      );
    const first = mergeWorkspace(target, source, LATER),
      second = mergeWorkspace(first, source, LATER);
    expect(second.evidence.length).toBe(first.evidence.length);
    expect(second.id).toBe(target.id);
    expect(result(second, "response.rehearsal", LATER).status).toBe("fail");
  });
  test("same asset ID with distinct subject is remapped safely", () => {
    const target = fixture(),
      source = fixture();
    source.assets[0]!.id = target.assets[0]!.id;
    source.assets[0]!.value = "other@example.test";
    source.assets[0]!.label = "Other owner email";
    const withEvidence = attest(
        source,
        "exposure.breach-review",
        "pass",
        source.assets[0]!.id,
      ),
      merged = mergeWorkspace(target, withEvidence, NOW);
    const imported = merged.evidence.find((e) => e.method === "import")!;
    expect(imported.assetId).not.toBe(target.assets[0]!.id);
    expect(merged.assets.find((a) => a.id === imported.assetId)!.value).toBe(
      "other@example.test",
    );
  });
  test("malformed imports fail cleanly for duplicate IDs, unknown checks, missing references and unknown fields", () => {
    const w = fixture();
    expect(() =>
      validateImport({ ...w, assets: [...w.assets, w.assets[0]!] }),
    ).toThrow();
    expect(() => validateImport({ ...w, evil: true })).toThrow();
    const missing = {
      ...w,
      evidence: [
        {
          id: "e1",
          checkId: "devices.firewall",
          assetId: "missing",
          status: "pass",
          method: "guided",
          observedAt: NOW,
          notes: NOTES,
        },
      ],
    };
    expect(WorkspaceSchema.safeParse(missing).success).toBe(false);
    expect(() =>
      validateImport({
        ...w,
        evidence: [{ ...missing.evidence[0], checkId: "invented" }],
      }),
    ).toThrow();
  });
  test("imported completed actions become plans without creating evidence", () => {
    const source = recordAction(
      createWorkspace("Source", NOW),
      { checkId: "response.rehearsal", status: "completed" },
      NOW,
    );
    const merged = mergeWorkspace(createWorkspace("Target", NOW), source, NOW);
    expect(merged.actions[0]!.status).toBe("planned");
    expect(merged.evidence).toEqual([]);
  });
  test("recovery cycles are review prompts and do not deduct points", () => {
    const w = fixture(),
      email = w.assets.find((a) => a.kind === "email")!,
      phone = w.assets.find((a) => a.kind === "phone")!;
    email.recoveryAssetIds = [phone.id];
    phone.recoveryAssetIds = [email.id];
    const findings = analyzeDependencies(w.assets);
    expect(
      findings.some(
        (f) => f.kind === "cycle" && f.message.includes("not itself a failure"),
      ),
    ).toBe(true);
    expect(evaluateWorkspace(w, NOW).score).toBeNull();
  });
  test("maximum supported inventory can save valid snapshots and dense recovery cycles stay bounded", () => {
    const w = createWorkspace("Maximum synthetic scope", NOW);
    w.assets = Array.from({ length: 200 }, (_, i) => ({
      id: `a${i}`,
      kind: "email",
      label: `Synthetic email ${i}`,
      critical: true,
      recoveryAssetIds: Array.from(
        { length: 100 },
        (_, j) => `a${(i + j + 1) % 200}`,
      ),
    }));
    const findings = analyzeDependencies(w.assets);
    expect(findings.filter((f) => f.kind === "cycle")).toHaveLength(1);
    expect(WorkspaceSchema.safeParse(createSnapshot(w, NOW)).success).toBe(
      true,
    );
  });
});
