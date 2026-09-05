import {
  CATEGORIES,
  CHECKS,
  CHECK_BY_ID,
  CATALOG_VERSION,
  SCORE_VERSION,
} from "./catalog";
import {
  AssetInputSchema,
  AssetPatchSchema,
  EvidenceInputSchema,
  ActionInputSchema,
  WorkspaceSchema,
  validateImport,
} from "./validation";
import type {
  Asset,
  AssetPatch,
  AuditSnapshot,
  CheckDefinition,
  CheckResult,
  CheckStatus,
  DependencyFinding,
  Evidence,
  EvidenceInput,
  Evaluation,
  Finding,
  RemediationAction,
  SubjectResult,
  Workspace,
} from "./types";

export function isoNow(now: string | Date = new Date()): string {
  const date = new Date(now);
  if (!Number.isFinite(date.getTime()))
    throw new Error("Invalid evaluation time.");
  return date.toISOString();
}
const id = (prefix: string) => `${prefix}_${crypto.randomUUID()}`;
const clone = <T>(value: T): T => structuredClone(value);
const resolved = (status: CheckStatus) =>
  status === "pass" || status === "partial" || status === "fail";
const attainment = (status: CheckStatus) =>
  status === "pass" ? 1 : status === "partial" ? 0.5 : 0;
const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };

// Reduced rational arithmetic avoids rounding drift when area points are redistributed.
class Fraction {
  n: bigint;
  d: bigint;
  constructor(n: bigint | number = 0, d: bigint | number = 1) {
    this.n = BigInt(n);
    this.d = BigInt(d);
    if (this.d <= 0n) throw new Error("Invalid denominator");
    const gcd = (a: bigint, b: bigint): bigint => (b ? gcd(b, a % b) : a);
    const g = gcd(this.n < 0n ? -this.n : this.n, this.d);
    this.n /= g;
    this.d /= g;
  }
  add(other: Fraction) {
    return new Fraction(this.n * other.d + other.n * this.d, this.d * other.d);
  }
  mul(other: Fraction) {
    return new Fraction(this.n * other.n, this.d * other.d);
  }
  percentOf(other: Fraction) {
    if (other.n === 0n) return 0;
    const n = this.n * other.d * 100n,
      d = this.d * other.n;
    return Number((2n * n + d) / (2n * d));
  }
  number() {
    return Number(this.n) / Number(this.d);
  }
}

export function createWorkspace(name: string, now?: string | Date): Workspace {
  const time = isoNow(now);
  return WorkspaceSchema.parse({
    schemaVersion: 1,
    id: id("ws"),
    name,
    createdAt: time,
    updatedAt: time,
    assets: [],
    evidence: [],
    actions: [],
    snapshots: [],
    threatEvents: [],
    settings: { region: "unspecified", modules: [], monitoring: false },
  });
}

function ensureSubject(
  workspace: Workspace,
  check: CheckDefinition,
  assetId?: string,
) {
  if (assetId) {
    const asset = workspace.assets.find((a) => a.id === assetId);
    if (!asset) throw new Error("Asset does not exist in this workspace.");
    if (!check.assetKinds?.includes(asset.kind))
      throw new Error("Asset does not match this check.");
  } else if (
    check.assetKinds &&
    workspace.assets.some((a) => check.assetKinds!.includes(a.kind))
  )
    throw new Error("Choose the asset this evidence concerns.");
}

export function recordEvidence(
  workspace: Workspace,
  input: EvidenceInput,
  now?: string | Date,
): Workspace {
  const parsed = EvidenceInputSchema.parse(input),
    time = isoNow(now),
    observedAt = parsed.observedAt ? isoNow(parsed.observedAt) : time;
  const check = CHECK_BY_ID.get(parsed.checkId)!;
  ensureSubject(workspace, check, parsed.assetId);
  if (Date.parse(observedAt) > Date.parse(time))
    throw new Error("Evidence cannot be observed in the future.");
  if (
    parsed.method !== "import" &&
    !check.acceptedMethods.includes(parsed.method)
  )
    throw new Error("This evidence method is not supported for this check.");
  if (parsed.status === "partial" && !check.partialCriteria)
    throw new Error(
      "This check has no defined partial-credit condition. Choose pass, fail or unknown.",
    );
  if (
    parsed.method === "guided" &&
    parsed.status !== "unknown" &&
    (parsed.notes?.trim().length ?? 0) < 16
  )
    throw new Error(
      "Describe the actual verification and result in at least 16 characters; an action being done is not evidence.",
    );
  if (
    parsed.status === "not_applicable" &&
    (parsed.notes?.trim().length ?? 0) < 16
  )
    throw new Error("Explain why this control does not apply.");
  if (
    check.assetKinds &&
    !parsed.assetId &&
    parsed.status !== "not_applicable" &&
    parsed.status !== "unknown"
  )
    throw new Error("Add and select an asset before verifying this check.");
  if (workspace.evidence.length >= 10000)
    throw new Error(
      "Evidence limit reached. Export your audit before starting a new workspace.",
    );
  const evidence: Evidence = { ...parsed, id: id("ev"), observedAt };
  return {
    ...clone(workspace),
    updatedAt: time,
    evidence: [...clone(workspace.evidence), evidence],
  };
}

export function addAsset(
  workspace: Workspace,
  input: Omit<Asset, "id">,
  now?: string | Date,
): Workspace {
  const asset = { ...AssetInputSchema.parse(input), id: id("asset") };
  if (
    asset.recoveryAssetIds?.some(
      (ref) => !workspace.assets.some((a) => a.id === ref),
    )
  )
    throw new Error("Recovery asset does not exist.");
  if (workspace.assets.length >= 200) throw new Error("Asset limit reached.");
  if (
    workspace.assets.some(
      (a) =>
        a.kind === asset.kind &&
        (a.value && asset.value
          ? a.value.trim().toLowerCase() === asset.value.trim().toLowerCase()
          : a.label.trim().toLowerCase() === asset.label.trim().toLowerCase()),
    )
  )
    throw new Error("This asset is already in the workspace.");
  return {
    ...clone(workspace),
    updatedAt: isoNow(now),
    assets: [...clone(workspace.assets), asset],
  };
}

type InvalidationReason =
  | "asset_identifier_changed"
  | "recovery_dependencies_changed";
function recoveryClosure(
  assets: Asset[],
  initial: Iterable<string>,
): Set<string> {
  const affected = new Set(initial);
  let changed = true;
  while (changed) {
    changed = false;
    for (const asset of assets)
      if (
        !affected.has(asset.id) &&
        asset.recoveryAssetIds?.some((ref) => affected.has(ref))
      ) {
        affected.add(asset.id);
        changed = true;
      }
  }
  return affected;
}
function invalidationRecords(
  evidence: Evidence[],
  reasonFor: (evidence: Evidence) => InvalidationReason | undefined,
  time: string,
): Evidence[] {
  const records = new Map<string, Evidence>();
  for (const item of evidence) {
    const invalidation = reasonFor(item),
      key = `${item.checkId}:${item.assetId}`;
    if (!invalidation || records.has(key)) continue;
    const notes =
      invalidation === "asset_identifier_changed"
        ? "The asset identifier changed. Previous observations were retained as history; verify this control for the current identifier."
        : "Recovery dependencies changed. Previous observations were retained as history; verify the current recovery routes and independent access.";
    records.set(key, {
      id: id("ev"),
      checkId: item.checkId,
      assetId: item.assetId,
      status: "unknown",
      method: "guided",
      observedAt: time,
      notes,
      facts: { invalidation },
    });
  }
  return [...records.values()];
}

/** Edit asset metadata without transferring verification to a different identity. */
export function updateAsset(
  workspace: Workspace,
  assetId: string,
  patch: AssetPatch,
  now?: string | Date,
): Workspace {
  const parsed = AssetPatchSchema.parse(patch),
    time = isoNow(now);
  const existing = workspace.assets.find((asset) => asset.id === assetId);
  if (!existing) throw new Error("Asset does not exist.");
  if (Date.parse(time) < Date.parse(workspace.updatedAt))
    throw new Error("Asset update cannot precede the latest workspace change.");
  const definedPatch = Object.fromEntries(
    Object.entries(parsed).filter(([, value]) => value !== undefined),
  );
  const replacement = { ...existing, ...definedPatch };
  if (parsed.value !== undefined) {
    const normalized = parsed.value.trim();
    if (normalized) replacement.value = normalized;
    else delete replacement.value;
  }
  const validated = {
    ...AssetInputSchema.parse({
      kind: replacement.kind,
      label: replacement.label,
      value: replacement.value,
      critical: replacement.critical,
      recoveryAssetIds: replacement.recoveryAssetIds,
    }),
    id: assetId,
  };
  if (
    validated.recoveryAssetIds?.some(
      (ref) => !workspace.assets.some((asset) => asset.id === ref),
    )
  )
    throw new Error("Recovery asset does not exist.");
  if (
    workspace.assets.some(
      (asset) =>
        asset.id !== assetId &&
        asset.kind === validated.kind &&
        (asset.value && validated.value
          ? asset.value.trim().toLowerCase() ===
            validated.value.trim().toLowerCase()
          : asset.label.trim().toLowerCase() ===
            validated.label.trim().toLowerCase()),
    )
  )
    throw new Error("This asset is already in the workspace.");
  const identifier = (asset: Asset) =>
    asset.kind === "email" || asset.kind === "domain"
      ? (asset.value?.trim().toLowerCase() ?? "")
      : (asset.value?.trim() ?? "");
  const identifierChanged = identifier(existing) !== identifier(validated);
  const recoveryChanged =
    JSON.stringify([...new Set(existing.recoveryAssetIds ?? [])].sort()) !==
    JSON.stringify([...(validated.recoveryAssetIds ?? [])].sort());
  const result = clone(workspace);
  result.assets = result.assets.map((asset) =>
    asset.id === assetId ? validated : asset,
  );
  result.updatedAt = time;

  // Invalidations are new unknown observations, so original evidence and snapshots remain intact.
  const recoverySubjects = new Set<string>();
  if (recoveryChanged) recoverySubjects.add(assetId);
  if (identifierChanged || recoveryChanged) {
    for (const dependent of recoveryClosure(workspace.assets, [assetId]))
      if (dependent !== assetId) recoverySubjects.add(dependent);
  }
  if (identifierChanged)
    result.threatEvents = result.threatEvents.map((event) =>
      event.assetId === assetId
        ? {
            ...event,
            relevance: "unassessed",
            description:
              `Historical report for a previous asset identifier. Recheck relevance to the current identifier. ${event.description}`.slice(
                0,
                3000,
              ),
          }
        : event,
    );
  const invalidations = invalidationRecords(
    workspace.evidence,
    (evidence) => {
      const direct = identifierChanged && evidence.assetId === assetId;
      const recovery = Boolean(
        evidence.assetId &&
          recoverySubjects.has(evidence.assetId) &&
          CHECK_BY_ID.get(evidence.checkId)?.categoryId === "recovery",
      );
      return direct
        ? "asset_identifier_changed"
        : recovery
          ? "recovery_dependencies_changed"
          : undefined;
    },
    time,
  );
  if (result.evidence.length + invalidations.length > 10000)
    throw new Error(
      "Evidence limit reached. Export your audit before editing an asset that requires reverification.",
    );
  result.evidence.push(...invalidations);
  return WorkspaceSchema.parse(result);
}

export function removeAsset(
  workspace: Workspace,
  assetId: string,
  now?: string | Date,
): Workspace {
  if (!workspace.assets.some((a) => a.id === assetId))
    throw new Error("Asset does not exist.");
  const time = isoNow(now);
  if (Date.parse(time) < Date.parse(workspace.updatedAt))
    throw new Error(
      "Asset removal cannot precede the latest workspace change.",
    );
  const affected = recoveryClosure(workspace.assets, [assetId]);
  const w = clone(workspace);
  w.assets = w.assets
    .filter((a) => a.id !== assetId)
    .map((a) => ({
      ...a,
      ...(a.recoveryAssetIds
        ? {
            recoveryAssetIds: a.recoveryAssetIds.filter(
              (ref) => ref !== assetId,
            ),
          }
        : {}),
    }));
  w.evidence = w.evidence.filter((e) => e.assetId !== assetId);
  const invalidations = invalidationRecords(
    w.evidence,
    (evidence) =>
      evidence.assetId &&
      affected.has(evidence.assetId) &&
      CHECK_BY_ID.get(evidence.checkId)?.categoryId === "recovery"
        ? "recovery_dependencies_changed"
        : undefined,
    time,
  );
  if (w.evidence.length + invalidations.length > 10000)
    throw new Error(
      "Evidence limit reached. Export your audit before removing an asset that requires recovery reverification.",
    );
  w.evidence.push(...invalidations);
  w.actions = w.actions.filter((a) => a.assetId !== assetId);
  w.threatEvents = w.threatEvents.map((event) =>
    event.assetId === assetId
      ? { ...event, assetId: undefined, relevance: "unassessed" }
      : event,
  );
  w.updatedAt = time;
  return WorkspaceSchema.parse(w);
}

export function recordAction(
  workspace: Workspace,
  input: Pick<RemediationAction, "checkId" | "assetId" | "status" | "notes">,
  now?: string | Date,
): Workspace {
  const parsed = ActionInputSchema.parse(input);
  ensureSubject(workspace, CHECK_BY_ID.get(parsed.checkId)!, parsed.assetId);
  const time = isoNow(now);
  const existing = workspace.actions.find(
    (a) => a.checkId === parsed.checkId && a.assetId === parsed.assetId,
  );
  if (!existing && workspace.actions.length >= 5000)
    throw new Error("Action limit reached.");
  const action: RemediationAction = {
    ...parsed,
    id: existing?.id ?? id("action"),
    createdAt: existing?.createdAt ?? time,
    updatedAt: time,
  };
  return {
    ...clone(workspace),
    updatedAt: time,
    actions: [
      ...clone(workspace.actions.filter((a) => a.id !== action.id)),
      action,
    ],
  };
}

function assessSubject(
  workspace: Workspace,
  check: CheckDefinition,
  assetId: string | undefined,
  time: string,
): SubjectResult {
  const evidence = workspace.evidence.filter(
    (e) => e.checkId === check.id && e.assetId === assetId,
  );
  const trusted = evidence.filter((e) => e.method !== "import");
  const candidates = trusted.length ? trusted : evidence;
  if (!candidates.length)
    return {
      assetId,
      status: "unknown",
      reason:
        check.assetKinds && !assetId
          ? "Add an applicable asset, or explicitly verify that this control does not apply."
          : "No observation has been recorded. Follow the verification procedure.",
    };
  const sorted = [...candidates].sort(
    (a, b) =>
      Date.parse(b.observedAt) - Date.parse(a.observedAt) ||
      a.id.localeCompare(b.id),
  );
  const latest = sorted[0]!,
    base = { assetId, evidenceId: latest.id };
  if (latest.method === "import")
    return {
      ...base,
      status: "imported",
      reason:
        "Imported evidence is historical and unverified. Perform a fresh check to earn verified points.",
    };
  if (Date.parse(latest.observedAt) > Date.parse(time))
    return {
      ...base,
      status: "unknown",
      reason:
        "Observation is dated after this evaluation and cannot count yet.",
    };
  if (!check.acceptedMethods.includes(latest.method))
    return {
      ...base,
      status: "unknown",
      reason: "This observation method is not accepted for this check.",
    };
  if (
    Date.parse(time) - Date.parse(latest.observedAt) >
    check.freshnessDays * 86_400_000
  )
    return {
      ...base,
      status: "stale",
      reason: `Evidence is older than the ${check.freshnessDays}-day verification window. Recheck the current state.`,
    };
  const contemporaries = sorted.filter(
    (e) =>
      Date.parse(e.observedAt) === Date.parse(latest.observedAt) &&
      e.method !== "import" &&
      check.acceptedMethods.includes(e.method),
  );
  const invalidation = contemporaries.find(
    (e) =>
      e.status === "unknown" &&
      (e.facts?.invalidation === "asset_identifier_changed" ||
        e.facts?.invalidation === "recovery_dependencies_changed"),
  );
  if (invalidation)
    return {
      assetId,
      evidenceId: invalidation.id,
      status: "unknown",
      reason: invalidation.notes!,
    };
  if (new Set(contemporaries.map((e) => e.status)).size > 1)
    return {
      ...base,
      status: "conflict",
      reason:
        "Observations at the same time disagree. Record a new observation after resolving the discrepancy.",
    };
  if (latest.status === "partial" && !check.partialCriteria)
    return {
      ...base,
      status: "unknown",
      reason:
        "Partial credit is not defined for this check. Reverify the result.",
    };
  if (
    ((latest.method === "guided" && latest.status !== "unknown") ||
      latest.status === "not_applicable") &&
    (latest.notes?.trim().length ?? 0) < 16
  )
    return {
      ...base,
      status: "unknown",
      reason:
        "The observation does not describe a sufficient verification procedure.",
    };
  if (check.assetKinds && !assetId && resolved(latest.status))
    return {
      ...base,
      status: "unknown",
      reason:
        "This observation has no asset context. Add the asset and reverify.",
    };
  return {
    ...base,
    status: latest.status,
    reason:
      latest.status === "pass"
        ? "Fresh accepted evidence verifies this control."
        : latest.status === "partial"
          ? check.partialCriteria!
          : latest.status === "fail"
            ? "Fresh accepted evidence confirms an open protective gap."
            : latest.status === "not_applicable"
              ? `Excluded from this area: ${latest.notes}`
              : (latest.notes ??
                "The check could not establish the current state."),
  };
}

export function evaluateWorkspace(
  workspace: Workspace,
  now?: string | Date,
): Evaluation {
  const time = isoNow(now);
  const results: CheckResult[] = CHECKS.map((check) => {
    if (
      (check.module && !workspace.settings.modules.includes(check.module)) ||
      (check.region &&
        workspace.settings.region !== "unspecified" &&
        workspace.settings.region.toUpperCase() !== check.region)
    )
      return {
        checkId: check.id,
        status: "not_applicable",
        earnedPoints: 0,
        maxPoints: 0,
        assessed: false,
        subjects: [],
        reason: "Excluded by the selected scope settings.",
      };
    const matching = check.assetKinds
      ? workspace.assets.filter((a) => check.assetKinds!.includes(a.kind))
      : [];
    const subjects: SubjectResult[] = matching.length
      ? matching.map((a) => assessSubject(workspace, check, a.id, time))
      : [assessSubject(workspace, check, undefined, time)];
    const applicable = subjects.filter((s) => s.status !== "not_applicable");
    const assessed =
      applicable.length > 0 && applicable.every((s) => resolved(s.status));
    let status: CheckStatus = "not_applicable";
    if (applicable.length) {
      if (assessed)
        status = applicable.reduce<CheckStatus>(
          (worst, s) =>
            attainment(s.status) < attainment(worst) ? s.status : worst,
          "pass",
        );
      else
        status =
          (["conflict", "stale", "imported", "unknown"] as CheckStatus[]).find(
            (s) => applicable.some((r) => r.status === s),
          ) ?? "unknown";
    }
    const one = subjects.length === 1 ? subjects[0] : undefined;
    const reason =
      one?.reason ??
      (status === "not_applicable"
        ? "All scoped assets are explicitly non-applicable."
        : assessed
          ? "Scored at the weakest result across all scoped assets. Additional healthy assets cannot dilute a gap."
          : "Every scoped asset needs fresh accepted evidence before this control is assessed.");
    return {
      checkId: check.id,
      ...(one?.assetId ? { assetId: one.assetId } : {}),
      ...(one?.evidenceId ? { evidenceId: one.evidenceId } : {}),
      status,
      earnedPoints: 0,
      maxPoints: 0,
      assessed,
      subjects,
      reason,
    };
  });
  let total = new Fraction(),
    earned = new Fraction(),
    assessedTotal = new Fraction();
  const categories = CATEGORIES.map((category) => {
    const entries = results.filter(
        (r) => CHECK_BY_ID.get(r.checkId)!.categoryId === category.id,
      ),
      applicable = entries.filter((r) => r.status !== "not_applicable");
    const totalWeight = applicable.reduce(
      (sum, r) => sum + CHECK_BY_ID.get(r.checkId)!.weight,
      0,
    );
    let categoryEarned = new Fraction(),
      categoryAssessed = new Fraction();
    if (totalWeight) {
      for (const entry of applicable) {
        const points = new Fraction(
          category.weight * CHECK_BY_ID.get(entry.checkId)!.weight,
          totalWeight,
        );
        entry.maxPoints = points.number();
        const earnedPoints = entry.assessed
          ? points.mul(new Fraction(attainment(entry.status) * 2, 2))
          : new Fraction();
        entry.earnedPoints = earnedPoints.number();
        categoryEarned = categoryEarned.add(earnedPoints);
        if (entry.assessed) categoryAssessed = categoryAssessed.add(points);
      }
    }
    const categoryMax = new Fraction(totalWeight ? category.weight : 0);
    total = total.add(categoryMax);
    earned = earned.add(categoryEarned);
    assessedTotal = assessedTotal.add(categoryAssessed);
    return {
      categoryId: category.id,
      score: categoryAssessed.n ? categoryEarned.percentOf(categoryMax) : null,
      coverage: categoryAssessed.percentOf(categoryMax),
      earnedPoints: categoryEarned.number(),
      maxPoints: categoryMax.number(),
      assessedPoints: categoryAssessed.number(),
      checkCount: applicable.length,
    };
  });
  const findings: Finding[] = [];
  for (const result of results) {
    const check = CHECK_BY_ID.get(result.checkId)!;
    for (const subject of result.subjects) {
      if (subject.status === "pass" || subject.status === "not_applicable")
        continue;
      const gap = subject.status === "fail" || subject.status === "partial";
      findings.push({
        id: `finding:${check.id}:${subject.assetId ?? "workspace"}`,
        checkId: check.id,
        ...(subject.assetId ? { assetId: subject.assetId } : {}),
        severity: gap
          ? check.severity
          : check.severity === "critical"
            ? "high"
            : "low",
        title: gap ? check.title : `Verify: ${check.title}`,
        description: subject.reason,
        kind: gap ? "gap" : "verification",
        action: gap ? check.remediation.steps[0]! : check.verification,
      });
    }
  }
  for (const [index, dependency] of analyzeDependencies(
    workspace.assets,
  ).entries())
    findings.push({
      id: `dependency:${index}`,
      checkId: "recovery.channels",
      assetId: dependency.assetIds[0],
      severity: dependency.severity,
      title: "Review recovery dependencies",
      description: dependency.message,
      kind: "dependency",
      action:
        "Review independent recovery options before changing any account access.",
    });
  findings.sort(
    (a, b) =>
      severityOrder[a.severity] - severityOrder[b.severity] ||
      (a.kind === "gap" ? 0 : 1) - (b.kind === "gap" ? 0 : 1) ||
      a.id.localeCompare(b.id),
  );
  return {
    score: total.n && assessedTotal.n ? earned.percentOf(total) : null,
    coverage: assessedTotal.percentOf(total),
    categories,
    checks: results,
    findings,
    evaluatedAt: time,
    catalogVersion: CATALOG_VERSION,
    scoreVersion: SCORE_VERSION,
  };
}

export function createSnapshot(
  workspace: Workspace,
  now?: string | Date,
): Workspace {
  if (workspace.snapshots.length >= 100)
    throw new Error(
      "Snapshot limit reached (100). Export this history before starting a new workspace.",
    );
  const time = isoNow(now),
    snapshot: AuditSnapshot = {
      id: id("audit"),
      createdAt: time,
      evaluation: evaluateWorkspace(workspace, time),
      assetIds: workspace.assets.map((a) => a.id),
      evidenceIds: workspace.evidence.map((e) => e.id),
      workspaceName: workspace.name,
      settings: clone(workspace.settings),
    };
  return {
    ...clone(workspace),
    updatedAt: time,
    snapshots: [...clone(workspace.snapshots), snapshot],
  };
}

export function analyzeDependencies(assets: Asset[]): DependencyFinding[] {
  const byId = new Map(assets.map((asset) => [asset.id, asset])),
    findings: DependencyFinding[] = [];
  for (const asset of assets) {
    const missing = [
      ...new Set(
        (asset.recoveryAssetIds ?? []).filter((ref) => !byId.has(ref)),
      ),
    ];
    if (missing.length)
      findings.push({
        kind: "missing",
        assetIds: [asset.id, ...missing],
        severity: "high",
        message: `${asset.label} references ${missing.length} missing recovery asset(s). Verify the actual recovery routes.`,
      });
    const valid = [
      ...new Set(asset.recoveryAssetIds?.filter((ref) => byId.has(ref)) ?? []),
    ];
    if (asset.critical && valid.length === 1)
      findings.push({
        kind: "single_point",
        assetIds: [asset.id, valid[0]!],
        severity: "medium",
        message: `${asset.label} has only one recorded recovery dependency. This is a review prompt, not proof that no independent recovery alternative exists.`,
      });
  }
  // One finding per strongly connected group: bounded linear traversal avoids enumerating
  // an exponential number of overlapping paths in a densely connected recovery graph.
  let nextIndex = 0;
  const indices = new Map<string, number>(),
    low = new Map<string, number>(),
    stack: string[] = [],
    onStack = new Set<string>();
  const visit = (current: string) => {
    indices.set(current, nextIndex);
    low.set(current, nextIndex++);
    stack.push(current);
    onStack.add(current);
    for (const next of byId.get(current)?.recoveryAssetIds ?? []) {
      if (!byId.has(next)) continue;
      if (!indices.has(next)) {
        visit(next);
        low.set(current, Math.min(low.get(current)!, low.get(next)!));
      } else if (onStack.has(next))
        low.set(current, Math.min(low.get(current)!, indices.get(next)!));
    }
    if (low.get(current) === indices.get(current)) {
      const group: string[] = [];
      let member: string;
      do {
        member = stack.pop()!;
        onStack.delete(member);
        group.push(member);
      } while (member !== current);
      if (
        group.length > 1 ||
        byId.get(current)?.recoveryAssetIds?.includes(current)
      )
        findings.push({
          kind: "cycle",
          assetIds: group.sort(),
          severity: "low",
          message:
            "Recorded recovery dependencies form a cycle. A cycle is not itself a failure; verify independent alternatives and recovery prerequisites.",
        });
    }
  };
  for (const asset of assets) if (!indices.has(asset.id)) visit(asset.id);
  return findings.sort(
    (a, b) =>
      a.kind.localeCompare(b.kind) ||
      a.assetIds.join().localeCompare(b.assetIds.join()),
  );
}

/** Merge without trusting imported scores, provider claims, identifiers or remediation proof. */
export function mergeWorkspace(
  workspace: Workspace,
  incoming: unknown,
  now?: string | Date,
): Workspace {
  const source = validateImport(incoming),
    time = isoNow(now),
    result = clone(workspace),
    mapping = new Map<string, string>();
  const sameAsset = (a: Asset, b: Asset) =>
    a.kind === b.kind &&
    (a.value && b.value
      ? a.value.trim().toLowerCase() === b.value.trim().toLowerCase()
      : a.label.trim().toLowerCase() === b.label.trim().toLowerCase());
  for (const asset of source.assets) {
    const existing = result.assets.find((a) => sameAsset(a, asset));
    if (existing) {
      existing.critical = existing.critical || asset.critical;
      mapping.set(asset.id, existing.id);
      continue;
    }
    const newId = id("asset");
    mapping.set(asset.id, newId);
    result.assets.push({ ...asset, id: newId, recoveryAssetIds: [] });
  }
  for (const asset of source.assets) {
    const target = result.assets.find((a) => a.id === mapping.get(asset.id))!;
    const importedRefs =
      asset.recoveryAssetIds?.map((ref) => mapping.get(ref)!).filter(Boolean) ??
      [];
    if (importedRefs.length)
      target.recoveryAssetIds = [
        ...new Set([...(target.recoveryAssetIds ?? []), ...importedRefs]),
      ];
  }
  for (const evidence of source.evidence) {
    const candidate = {
      ...evidence,
      assetId: evidence.assetId ? mapping.get(evidence.assetId) : undefined,
      method: "import" as const,
    };
    const duplicate = result.evidence.some(
      (e) =>
        e.method === "import" &&
        e.checkId === candidate.checkId &&
        e.assetId === candidate.assetId &&
        e.observedAt === candidate.observedAt &&
        e.status === candidate.status &&
        e.notes === candidate.notes &&
        JSON.stringify(e.facts) === JSON.stringify(candidate.facts),
    );
    if (!duplicate) result.evidence.push({ ...candidate, id: id("ev") });
  }
  // Imported actions are proposals; never replace existing completion records or create proof.
  for (const action of source.actions) {
    const assetId = action.assetId ? mapping.get(action.assetId) : undefined;
    if (
      !result.actions.some(
        (a) => a.checkId === action.checkId && a.assetId === assetId,
      )
    )
      result.actions.push({
        ...action,
        id: id("action"),
        assetId,
        status: "planned",
        createdAt: time,
        updatedAt: time,
      });
  }
  for (const event of source.threatEvents) {
    if (
      !result.threatEvents.some(
        (e) =>
          e.source === event.source &&
          e.url === event.url &&
          e.title === event.title,
      )
    )
      result.threatEvents.push({
        ...event,
        id: id("threat"),
        assetId: event.assetId ? mapping.get(event.assetId) : undefined,
        relevance: "unassessed",
      });
  }
  result.updatedAt = time;
  return WorkspaceSchema.parse(result);
}
