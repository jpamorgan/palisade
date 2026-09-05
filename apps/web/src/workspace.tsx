import {
  useState,
  useCallback,
  useRef,
  type FormEvent,
  type ReactNode,
} from "react";
import { Link, useSearchParams } from "react-router-dom";
import {
  ArrowRightIcon,
  ArrowPathIcon,
  PlusIcon,
  CheckCircleIcon,
  MagnifyingGlassIcon,
  ChevronRightIcon,
  ArrowDownTrayIcon,
} from "@heroicons/react/16/solid";
import {
  CATEGORIES,
  CHECKS,
  analyzeDependencies,
  type CheckDefinition,
  type CheckResult,
  type EvidenceStatus,
  type AssetKind,
  type Asset,
} from "@palisade/core";
import { authClient } from "./auth";
import { AuthPanel } from "./auth-panel";
import { Settings, Exposure } from "./settings";
import { useAudit, date, auditHref } from "./data";
import {
  Brand,
  ScoreRing,
  PageHeading,
  EmptyState,
  ErrorMessage,
  Loading,
  Modal,
  Field,
  Status,
  Meter,
} from "./ui";

export function WorkspaceShell() {
  const { data, loading, error, demo, refresh } = useAudit();
  const { data: session } = authClient.useSession();
  const [params, setParams] = useSearchParams();
  const moreRef = useRef<HTMLDetailsElement>(null);
  const [accountError, setAccountError] = useState<unknown>(null);
  const panel = params.get("panel");
  const auth = params.get("auth");
  function openPanel(value: string) {
    if (moreRef.current) moreRef.current.open = false;
    setParams((p) => {
      p.set("panel", value);
      p.delete("auth");
      return p;
    });
  }
  function openAuth(value: string) {
    if (moreRef.current) moreRef.current.open = false;
    setParams((p) => {
      p.set("auth", value);
      return p;
    });
  }
  const closePanel = useCallback(
    () =>
      setParams((p) => {
        p.delete("panel");
        return p;
      }),
    [setParams],
  );
  const closeAuth = useCallback(
    () =>
      setParams((p) => {
        p.delete("auth");
        return p;
      }),
    [setParams],
  );
  const panels: Record<string, { title: string; content: ReactNode }> = {
    assets: { title: "Accounts & devices", content: <Assets /> },
    settings: { title: "Settings", content: <Settings /> },
    exposure: { title: "Exposure checks", content: <Exposure /> },
    history: { title: "Audit history", content: <History /> },
  };
  const activePanel = panel ? panels[panel] : undefined;
  return (
    <div className="single-app">
      <header className="single-header">
        <Brand />
        <div className="single-tools">
          <button
            type="button"
            className="header-tool desktop-tool"
            onClick={() => openPanel("assets")}
          >
            Accounts & devices
          </button>
          <button
            type="button"
            className="header-tool desktop-tool"
            onClick={() => openPanel("settings")}
          >
            Settings
          </button>
          <details className="more-menu" ref={moreRef}>
            <summary>
              More <ChevronRightIcon />
            </summary>
            <div>
              <button
                type="button"
                className="mobile-tool"
                onClick={() => openPanel("assets")}
              >
                Accounts & devices
              </button>
              <button
                type="button"
                className="mobile-tool"
                onClick={() => openPanel("settings")}
              >
                Settings
              </button>
              <button type="button" onClick={() => openPanel("exposure")}>
                Exposure checks
              </button>
              <button type="button" onClick={() => openPanel("history")}>
                Audit history
              </button>
              <a
                href="https://github.com/jpamorgan/palisade#api-and-mcp"
                target="_blank"
                rel="noreferrer"
              >
                CLI & MCP documentation
              </a>
              {!session && (
                <button
                  type="button"
                  className="mobile-tool"
                  onClick={() => openAuth("signin")}
                >
                  Sign in
                </button>
              )}
              {session && (
                <button
                  type="button"
                  onClick={async () => {
                    setAccountError(null);
                    try {
                      const result = await authClient.signOut();
                      if (result.error) throw new Error(result.error.message);
                      setParams({ demo: "1" });
                    } catch (error) {
                      setAccountError(error);
                    }
                  }}
                >
                  Sign out
                </button>
              )}
            </div>
          </details>
          {!session ? (
            <>
              <button
                type="button"
                className="header-tool signin-tool"
                onClick={() => openAuth("signin")}
              >
                Sign in
              </button>
              <button
                type="button"
                className="button primary"
                onClick={() => openAuth("signup")}
              >
                Get started
              </button>
            </>
          ) : demo ? (
            <button
              type="button"
              className="button secondary"
              onClick={() => setParams({})}
            >
              My workspace
            </button>
          ) : (
            <span className="private-label">
              <span className="live-dot" />
              Private workspace
            </span>
          )}
        </div>
      </header>
      {accountError ? (
        <div className="header-error">
          <ErrorMessage error={accountError} />
        </div>
      ) : null}
      {demo && (
        <div className="single-demo">
          <span>
            <strong>Interactive demo.</strong> Sample data; changes stay in this
            tab.
          </span>
          {!session && (
            <button type="button" onClick={() => openAuth("signup")}>
              Start your own checklist <ArrowRightIcon />
            </button>
          )}
        </div>
      )}
      <main className="single-main" id="main-content">
        {loading ? (
          <Loading />
        ) : error ? (
          <EmptyState
            title="Couldn’t open your checklist"
            description={error.message}
            action={
              <button
                type="button"
                className="button secondary"
                onClick={refresh}
              >
                Try again
              </button>
            }
          />
        ) : data ? (
          <Checklist />
        ) : null}
      </main>
      {auth && (
        <Modal
          key={`auth-${auth}`}
          title={auth === "signup" ? "Create your workspace" : "Sign in"}
          onClose={closeAuth}
        >
          <AuthPanel signup={auth === "signup"} />
        </Modal>
      )}
      {!auth && activePanel && (
        <Modal key={panel} title={activePanel.title} onClose={closePanel} wide>
          <div className="utility-content">{activePanel.content}</div>
        </Modal>
      )}
    </div>
  );
}
export function Checklist() {
  const { data, base, mutate, pending, notify } = useAudit();
  const [params, setParams] = useSearchParams();
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("all");
  const [error, setError] = useState<unknown>(null);
  const area = params.get("area") ?? "all";
  const selected = CHECKS.find((c) => c.id === params.get("check"));
  const close = useCallback(
    () =>
      setParams((p) => {
        p.delete("check");
        p.delete("asset");
        return p;
      }),
    [setParams],
  );
  if (!data) return null;
  const { workspace, evaluation } = data;
  const applicable = evaluation.checks.filter((r) => r.maxPoints > 0);
  const assessed = applicable.filter((r) => r.assessed).length;
  const needsAttention = (result?: CheckResult) =>
    result?.subjects.some((s) =>
      ["fail", "partial", "stale", "conflict", "imported"].includes(s.status),
    ) ||
    ["fail", "partial", "stale", "conflict", "imported"].includes(
      result?.status ?? "",
    );
  const visible = CHECKS.filter((c) => {
    const result = evaluation.checks.find((r) => r.checkId === c.id);
    return (
      (area === "all" || c.categoryId === area) &&
      `${c.title} ${c.description}`
        .toLowerCase()
        .includes(search.toLowerCase()) &&
      (filter === "all" ||
        (filter === "unchecked" &&
          !result?.assessed &&
          result?.maxPoints !== 0) ||
        (filter === "attention" && needsAttention(result)))
    );
  });
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  const priorityChecks = [...evaluation.findings]
    .filter((f) => f.kind !== "dependency")
    .sort(
      (a, b) =>
        (a.kind === "gap" ? 0 : 1) - (b.kind === "gap" ? 0 : 1) ||
        severityOrder[a.severity] - severityOrder[b.severity],
    )
    .filter(
      (finding, index, all) =>
        all.findIndex((f) => f.checkId === finding.checkId) === index,
    )
    .slice(0, 2);
  function openCheck(checkId: string, assetId?: string) {
    setParams((p) => {
      p.set("check", checkId);
      if (assetId) p.set("asset", assetId);
      else p.delete("asset");
      return p;
    });
  }
  function checkOrder(check: CheckDefinition) {
    const result = evaluation.checks.find((r) => r.checkId === check.id);
    const state = needsAttention(result)
      ? 0
      : !result?.assessed && result?.maxPoints !== 0
        ? 1
        : 2;
    return state * 10 + severityOrder[check.severity];
  }
  async function audit() {
    setError(null);
    try {
      await mutate("/audits", {});
      notify(
        "Audit saved. Current evidence and freshness have been reevaluated.",
      );
    } catch (e) {
      setError(e);
    }
  }
  return (
    <div className="simple-checklist">
      <header className="checklist-page-heading">
        <div>
          <h1>Your security checklist</h1>
        </div>
        <div className="checklist-utilities">
          <button
            type="button"
            className="button secondary"
            disabled={pending}
            onClick={audit}
          >
            <ArrowPathIcon />
            {pending ? "Saving…" : "Re-audit"}
          </button>
        </div>
      </header>
      <ErrorMessage error={error} />
      <section
        className="checklist-progress"
        aria-label="Current audit progress"
      >
        <div className="progress-metric">
          <div className="progress-label">
            <h2>Security posture</h2>
            <a
              href="https://github.com/jpamorgan/palisade/blob/main/docs/methodology.md"
              target="_blank"
              rel="noreferrer"
              aria-label="How the posture score works"
            >
              How it’s scored
            </a>
          </div>
          <div className="progress-value">
            {evaluation.score === null ? "—" : evaluation.score}
            <span>/100</span>
          </div>
          <Meter value={evaluation.score ?? 0} />
        </div>
        <div className="progress-metric">
          <div className="progress-label">
            <h2>Assessment coverage</h2>
            <p>
              {assessed} of {applicable.length} checks
            </p>
          </div>
          <div className="progress-value">
            {evaluation.coverage}
            <span>%</span>
          </div>
          <Meter value={evaluation.coverage} />
        </div>
      </section>
      {workspace.assets.length === 0 ? (
        <div className="checklist-onboarding">
          <div>
            <h2>Start with your primary email</h2>
            <p>Add the account you use to recover everything else.</p>
          </div>
          <Link
            className="button primary"
            to={auditHref(base, { panel: "assets" })}
          >
            Add your first account <PlusIcon />
          </Link>
        </div>
      ) : priorityChecks.length > 0 ? (
        <section className="priority-checks">
          <div className="priority-heading">
            <h2>Recommended next</h2>
          </div>
          <ol className="priority-list" role="list">
            {priorityChecks.map((finding, index) => (
              <li key={finding.id}>
                <button
                  type="button"
                  onClick={() => openCheck(finding.checkId, finding.assetId)}
                >
                  <span className="priority-number">{index + 1}</span>
                  <span className="priority-copy">
                    <strong>{finding.title}</strong>
                    <span>
                      {finding.assetId
                        ? workspace.assets.find((a) => a.id === finding.assetId)
                            ?.label
                        : CATEGORIES.find(
                            (c) =>
                              c.id ===
                              CHECKS.find(
                                (check) => check.id === finding.checkId,
                              )?.categoryId,
                          )?.name}
                    </span>
                  </span>
                  <span className={`severity severity-${finding.severity}`}>
                    {finding.severity} priority
                  </span>
                  <ChevronRightIcon />
                </button>
              </li>
            ))}
          </ol>
        </section>
      ) : (
        <p className="checklist-clear">
          Your assessed protections are up to date. Re-audit when something
          changes.
        </p>
      )}
      <div className="checklist-filters">
        <div className="search-input">
          <MagnifyingGlassIcon />
          <input
            name="search"
            aria-label="Search checks"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Find a check…"
          />
        </div>
        <select
          name="check-filter"
          aria-label="Filter check status"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        >
          <option value="all">All checks</option>
          <option value="attention">Needs attention</option>
          <option value="unchecked">Not assessed</option>
        </select>
        {area !== "all" && (
          <button
            type="button"
            className="button ghost"
            onClick={() =>
              setParams((p) => {
                p.delete("area");
                return p;
              })
            }
          >
            Show all areas
          </button>
        )}
      </div>
      <div className="grouped-checklist">
        {visible.length ? (
          CATEGORIES.filter((c) =>
            visible.some((check) => check.categoryId === c.id),
          ).map((category, index) => {
            const categoryResult = evaluation.categories.find(
              (r) => r.categoryId === category.id,
            );
            const scoped = applicable.filter(
              (r) =>
                CHECKS.find((c) => c.id === r.checkId)?.categoryId ===
                category.id,
            );
            const completed = scoped.filter((r) => r.assessed).length;
            const attention = scoped.filter(needsAttention).length;
            const checks = visible
              .filter((c) => c.categoryId === category.id)
              .sort((a, b) => checkOrder(a) - checkOrder(b));
            return (
              <details
                className="audit-area"
                key={`${category.id}:${search}:${filter}:${area}`}
                open={
                  Boolean(search) || filter !== "all" || area === category.id
                }
              >
                <summary>
                  <ChevronRightIcon className="area-chevron" />
                  <h2>{category.name}</h2>
                  <div className="area-completion">
                    {attention > 0 && (
                      <span className="area-attention">
                        {attention} need attention
                      </span>
                    )}
                    <p>
                      {scoped.length
                        ? `${completed} of ${scoped.length} assessed`
                        : "Not applicable"}
                    </p>
                    <Meter value={categoryResult?.coverage ?? 0} />
                  </div>
                </summary>
                <div className="area-checks">
                  {checks.map((check) => {
                    const result = evaluation.checks.find(
                      (r) => r.checkId === check.id,
                    );
                    const knownGaps =
                      result?.subjects.filter(
                        (s) => s.status === "fail" || s.status === "partial",
                      ).length ?? 0;
                    return (
                      <button
                        type="button"
                        className="compact-check"
                        key={check.id}
                        onClick={() => openCheck(check.id)}
                      >
                        <div
                          className={`check-symbol ${result?.status === "pass" ? "is-pass" : ""}`}
                        >
                          {result?.status === "pass" ? (
                            <CheckCircleIcon />
                          ) : (
                            <span />
                          )}
                        </div>
                        <span className="compact-check-title">
                          {check.title}
                          {result?.status === "unknown" && knownGaps > 0 && (
                            <span className="compact-gap">
                              {knownGaps}{" "}
                              {knownGaps === 1 ? "asset needs" : "assets need"}{" "}
                              attention
                            </span>
                          )}
                        </span>
                        <Status status={result?.status ?? "unknown"} />
                        <ChevronRightIcon />
                      </button>
                    );
                  })}
                </div>
              </details>
            );
          })
        ) : (
          <EmptyState
            title="No checks match"
            description="Try a different search or filter."
            action={
              <button
                type="button"
                className="button secondary"
                onClick={() => {
                  setSearch("");
                  setFilter("all");
                  setParams({});
                }}
              >
                Clear filters
              </button>
            }
          />
        )}
      </div>
      <p className="checklist-footnote">
        Unassessed is not the same as failed. A completed action earns points
        only after you verify the protection.
      </p>
      {selected && !params.has("panel") && !params.has("auth") && (
        <CheckDialog
          key={`${selected.id}:${params.get("asset") ?? ""}`}
          initialAssetId={params.get("asset") ?? undefined}
          check={selected}
          result={evaluation.checks.find((r) => r.checkId === selected.id)}
          onClose={close}
        />
      )}
    </div>
  );
}
function CheckDialog({
  initialAssetId,
  check,
  result,
  onClose,
}: {
  initialAssetId?: string;
  check: CheckDefinition;
  result?: CheckResult;
  onClose: () => void;
}) {
  const { data, mutate, pending, notify, demo } = useAudit();
  const [, setParams] = useSearchParams();
  function openTool(panel: string) {
    setParams((params) => {
      params.set("panel", panel);
      if (assetId) params.set("asset", assetId);
      return params;
    });
  }
  const assets = data!.workspace.assets.filter((a) =>
    check.assetKinds?.includes(a.kind),
  );
  const [assetId, setAssetId] = useState(
    (assets.some((a) => a.id === initialAssetId)
      ? initialAssetId
      : undefined) ??
      result?.subjects.find(
        (s) => s.status === "fail" || s.status === "partial",
      )?.assetId ??
      result?.subjects.find((s) => s.status !== "pass")?.assetId ??
      assets[0]?.id ??
      "",
  );
  const [status, setStatus] = useState<EvidenceStatus>("pass");
  const [notes, setNotes] = useState("");
  const [tab, setTab] = useState("verify");
  const [error, setError] = useState<unknown>(null);
  const [question, setQuestion] = useState("");
  const [answer, setAnswer] = useState("");
  const [asking, setAsking] = useState(false);
  const subject = result?.subjects.find(
    (s) => s.assetId === (assetId || undefined),
  );
  const evidence = data!.workspace.evidence.find(
    (e) => e.id === subject?.evidenceId,
  );
  const latestAction = data!.workspace.actions
    .filter(
      (a) => a.checkId === check.id && a.assetId === (assetId || undefined),
    )
    .at(-1);
  async function save(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await mutate("/evidence", {
        checkId: check.id,
        ...(assetId ? { assetId } : {}),
        status,
        notes,
      });
      notify("Evidence recorded. Your posture has been recalculated.");
    } catch (e) {
      setError(e);
    }
  }
  async function action(actionStatus: "planned" | "completed") {
    setError(null);
    try {
      await mutate("/actions", {
        checkId: check.id,
        ...(assetId ? { assetId } : {}),
        status: actionStatus,
        notes,
      });
      notify(
        actionStatus === "completed"
          ? "Action completed. Verify the resulting protection to update your score."
          : "Action added to your plan.",
      );
    } catch (e) {
      setError(e);
    }
  }
  async function ask(e: FormEvent) {
    e.preventDefault();
    setAsking(true);
    setError(null);
    try {
      const response = await mutate<{ answer: string }>("/assistant", {
        message: question,
        checkId: check.id,
      });
      setAnswer(response.answer);
    } catch (e) {
      setError(e);
    } finally {
      setAsking(false);
    }
  }
  return (
    <Modal title={check.title} onClose={onClose} wide>
      <div className="check-dialog-content">
        <div className="check-dialog-intro">
          <Status status={subject?.status ?? result?.status ?? "unknown"} />
          <span className={`severity severity-${check.severity}`}>
            {check.severity} priority
          </span>
          <p>{check.description}</p>
        </div>
        {check.assetKinds?.length ? (
          <Field name="evidence-asset" label="Account or device being checked">
            {assets.length ? (
              <select
                name="assetId"
                id="evidence-asset"
                value={assetId}
                onChange={(e) => setAssetId(e.target.value)}
              >
                {assets.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.label}
                    {a.critical ? " · Important" : ""}
                  </option>
                ))}
              </select>
            ) : (
              <div className="inline-note">
                <p>
                  Add a matching account or device to record protection. If you
                  have none, you can mark this check not applicable or unknown.
                </p>
                <button
                  type="button"
                  className="button secondary"
                  onClick={() => openTool("assets")}
                >
                  Accounts & devices <ArrowRightIcon />
                </button>
              </div>
            )}
          </Field>
        ) : null}
        <div className="dialog-tabs">
          <button
            type="button"
            className={tab === "verify" ? "active" : ""}
            onClick={() => setTab("verify")}
          >
            Verify protection
          </button>
          <button
            type="button"
            className={tab === "mitigate" ? "active" : ""}
            onClick={() => setTab("mitigate")}
          >
            Make an improvement
          </button>
        </div>
        {tab === "verify" ? (
          <>
            <div className="verification-instructions">
              <h3>How to verify</h3>
              <p>{check.verification}</p>
              {check.partialCriteria && (
                <p className="field-hint">
                  <strong>Partial protection:</strong> {check.partialCriteria}
                </p>
              )}
            </div>
            <details className="check-guidance">
              <summary>Step-by-step guidance</summary>
              <ol className="steps">
                {check.guidance.map((step, index) => (
                  <li key={index}>{step}</li>
                ))}
              </ol>
            </details>
            {check.acceptedMethods.includes("provider") && (
              <button
                type="button"
                className="button secondary provider-shortcut"
                onClick={() => openTool("exposure")}
              >
                Check Have I Been Pwned <ArrowRightIcon />
              </button>
            )}
            <form onSubmit={save}>
              <Field name="evidence-status" label="What did you verify?">
                <select
                  name="status"
                  id="evidence-status"
                  value={status}
                  onChange={(e) => setStatus(e.target.value as EvidenceStatus)}
                >
                  <option value="pass">
                    Protected — verified all requirements
                  </option>
                  {check.partialCriteria && (
                    <option value="partial">Partially protected</option>
                  )}
                  <option value="fail">Not protected — needs attention</option>
                  <option value="unknown">I couldn’t verify this</option>
                  <option value="not_applicable">This does not apply</option>
                </select>
              </Field>
              <Field
                name="evidence-notes"
                label="Verification notes"
                hint="Record what you checked. Never include passwords, codes, or secrets."
              >
                <textarea
                  name="notes"
                  id="evidence-notes"
                  rows={3}
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  minLength={16}
                  required
                  maxLength={2000}
                  placeholder="Where you checked, what you observed, and any limitations…"
                />
              </Field>
              {!check.acceptedMethods.includes("guided") && (
                <div className="inline-note">
                  <p>
                    This check requires {check.acceptedMethods.join(" or ")}{" "}
                    evidence. Use the corresponding scan or local collector to
                    verify it.
                  </p>
                </div>
              )}
              <ErrorMessage error={error} />
              <button
                type="submit"
                className="button primary"
                disabled={
                  pending ||
                  !check.acceptedMethods.includes("guided") ||
                  Boolean(
                    check.assetKinds?.length &&
                    !assetId &&
                    !["unknown", "not_applicable"].includes(status),
                  )
                }
              >
                {pending ? "Saving…" : "Record verification"}
                <CheckCircleIcon />
              </button>
            </form>
          </>
        ) : (
          <>
            <h3>{check.remediation.title}</h3>
            {check.remediation.lockoutRisk && (
              <div className="caution-note">
                <strong>Preserve your way back in.</strong>
                <p>
                  This change can affect account access. Confirm a working
                  recovery method before you begin.
                </p>
              </div>
            )}
            <ol className="steps">
              {check.remediation.steps.map((s, i) => (
                <li key={i}>{s}</li>
              ))}
            </ol>
            <div className="verification-note">
              <h4>If something goes wrong</h4>
              <p>{check.remediation.rollback}</p>
            </div>
            {latestAction && (
              <p className="inline-note">
                Action status: <strong>{latestAction.status}</strong> ·{" "}
                {date(latestAction.updatedAt)}
              </p>
            )}
            <p className="muted">
              Completing an action records your progress. Verify the protection
              separately to earn score credit.
            </p>
            <ErrorMessage error={error} />
            <div className="row">
              <button
                type="button"
                className="button secondary"
                disabled={pending}
                onClick={() => action("planned")}
              >
                Add to my plan
              </button>
              <button
                type="button"
                className="button primary"
                disabled={pending}
                onClick={() => action("completed")}
              >
                Mark action completed <CheckCircleIcon />
              </button>
            </div>
          </>
        )}
        <details className="evidence-disclosure">
          <summary>Evidence & score details</summary>
          <div className="evidence-disclosure-content">
            <h3>The evidence behind this result</h3>
            <p>
              {subject?.reason ?? result?.reason ?? "No evidence recorded yet."}
            </p>
            {result && result.subjects.length > 1 && (
              <div className="verification-note">
                <h4>Why the overall check has this score</h4>
                <p>{result.reason}</p>
                <p>
                  This contribution covers all relevant assets. A verified
                  result for one asset does not stand in for the others.
                </p>
              </div>
            )}
            <dl className="evidence-facts">
              <div>
                <dt>Evidence method</dt>
                <dd>{evidence?.method ?? "Not recorded"}</dd>
              </div>
              <div>
                <dt>Observed</dt>
                <dd>{date(evidence?.observedAt)}</dd>
              </div>
              <div>
                <dt>Freshness window</dt>
                <dd>{check.freshnessDays} days</dd>
              </div>
              <div>
                <dt>Score contribution</dt>
                <dd>
                  {(result?.earnedPoints ?? 0).toFixed(2)} /{" "}
                  {(result?.maxPoints ?? 0).toFixed(2)} points
                </dd>
              </div>
            </dl>
            {evidence?.notes && (
              <div className="verification-note">
                <h4>Notes</h4>
                <p className="preserve-space">{evidence.notes}</p>
              </div>
            )}
            {result?.subjects.length && result.subjects.length > 1 ? (
              <>
                <h3>Across your accounts and devices</h3>
                {result.subjects.map((s, i) => (
                  <div className="subject-row" key={s.assetId ?? i}>
                    <span>
                      {data!.workspace.assets.find((a) => a.id === s.assetId)
                        ?.label ?? "Workspace"}
                    </span>
                    <Status status={s.status} />
                  </div>
                ))}
              </>
            ) : null}
            <a
              href="https://github.com/jpamorgan/palisade/blob/main/docs/methodology.md"
              target="_blank"
              rel="noreferrer"
              className="text-link"
            >
              Read the scoring methodology <ArrowRightIcon />
            </a>
          </div>
        </details>

        <details className="assistant-details">
          <summary>Ask about this check</summary>
          <p>
            Get optional AI guidance. Keep private identifiers out of your
            question. Guidance cannot change your settings or verify a control.
          </p>
          {demo ? (
            <p>Create your own workspace to use live guidance.</p>
          ) : (
            <form onSubmit={ask}>
              <Field name="question" label="Your question">
                <textarea
                  id="question"
                  name="question"
                  value={question}
                  onChange={(e) => setQuestion(e.target.value)}
                  required
                  maxLength={1000}
                  rows={2}
                />
              </Field>
              <button
                type="submit"
                className="button secondary"
                disabled={asking}
              >
                {asking ? "Thinking…" : "Ask for guidance"}
              </button>
            </form>
          )}
          {answer && (
            <p className="assistant-answer preserve-space">{answer}</p>
          )}
        </details>
      </div>
    </Modal>
  );
}
export function Assets() {
  const { data, mutate, pending, notify } = useAudit();
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<Asset | null>(null);
  const [removing, setRemoving] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [kind, setKind] = useState<AssetKind>("email");
  const close = useCallback(() => {
    setAdding(false);
    setEditing(null);
    setError(null);
  }, []);
  if (!data) return null;
  const dependencies = analyzeDependencies(data.workspace.assets);
  async function add(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    const f = new FormData(e.currentTarget);
    try {
      await mutate(
        editing ? `/assets/${editing.id}` : "/assets",
        {
          ...(!editing ? { kind } : {}),
          label: String(f.get("label")),
          value: String(f.get("value") ?? "") || (editing ? "" : undefined),
          critical: f.get("critical") === "on",
          recoveryAssetIds: f.getAll("recovery").map(String),
        },
        editing ? "PATCH" : "POST",
      );
      setAdding(false);
      setEditing(null);
      notify(
        editing
          ? "Asset updated. Changed identifiers and recovery paths need fresh verification."
          : "Asset added. Relevant checks now include it.",
      );
    } catch (e) {
      setError(e);
    }
  }
  async function remove() {
    setError(null);
    try {
      await mutate(`/assets/${removing}`, undefined, "DELETE");
      setRemoving(null);
      notify("Asset removed. Previous audit snapshots are preserved.");
    } catch (e) {
      setError(e);
    }
  }
  return (
    <>
      <PageHeading
        eyebrow="The things you’re protecting"
        title="Accounts & devices"
        description="Map your important assets so evidence applies to the right place."
        action={
          <button
            type="button"
            className="button primary"
            onClick={() => {
              setEditing(null);
              setKind("email");
              setAdding(true);
            }}
          >
            <PlusIcon />
            Add an asset
          </button>
        }
      />
      {data.workspace.assets.length ? (
        <div className="asset-list">
          {data.workspace.assets.map((a) => (
            <article key={a.id} className="asset-row">
              <div className="asset-kind">{a.kind.replace("_", " ")}</div>
              <div>
                <h3>
                  {a.label}
                  {a.critical && <span className="quiet-badge">Important</span>}
                </h3>
                <p>{a.value ?? "Identifier kept private"}</p>
                {a.recoveryAssetIds?.length ? (
                  <p className="muted">
                    Recovered through:{" "}
                    {a.recoveryAssetIds
                      .map(
                        (id) =>
                          data.workspace.assets.find((x) => x.id === id)
                            ?.label ?? "Missing asset",
                      )
                      .join(", ")}
                  </p>
                ) : null}
              </div>
              <button
                type="button"
                className="button secondary"
                aria-label={`Edit ${a.label}`}
                onClick={() => {
                  setEditing(a);
                  setKind(a.kind);
                  setAdding(true);
                }}
              >
                Edit
              </button>
              <button
                type="button"
                className="button ghost"
                aria-label={`Remove ${a.label}`}
                onClick={() => setRemoving(a.id)}
              >
                Remove
              </button>
            </article>
          ))}
        </div>
      ) : (
        <EmptyState
          title="Start with your primary email"
          description="It often holds the keys to your other accounts. Add it, then the devices and accounts you depend on."
          action={
            <button
              type="button"
              className="button secondary"
              onClick={() => setAdding(true)}
            >
              <PlusIcon />
              Add your first asset
            </button>
          }
        />
      )}
      <section className="dependency-section">
        <h2>Your recovery connections</h2>
        <p>
          Understand how one account or device can help you recover another.
        </p>
        {dependencies.length ? (
          dependencies.map((d, i) => (
            <div className="caution-note" key={i}>
              <p>{d.message}</p>
            </div>
          ))
        ) : (
          <div className="verification-note">
            <p>
              {data.workspace.assets.some((a) => a.recoveryAssetIds?.length)
                ? "No missing or circular recovery links were identified in the relationships you provided."
                : "Add recovery connections when creating assets to identify circular dependencies and missing recovery paths."}
            </p>
          </div>
        )}
      </section>
      {adding && (
        <Modal
          title={
            editing ? "Edit account or device" : "Add an account or device"
          }
          onClose={close}
        >
          <form className="modal-form" onSubmit={add}>
            <Field name="asset-kind" label="Type">
              <select
                id="asset-kind"
                name="kind"
                disabled={!!editing}
                value={kind}
                onChange={(e) => setKind(e.target.value as AssetKind)}
              >
                {(
                  [
                    "email",
                    "phone",
                    "device",
                    "domain",
                    "financial",
                    "password_manager",
                    "identity",
                    "network",
                  ] as const
                ).map((k) => (
                  <option key={k} value={k}>
                    {k.replace("_", " ")}
                  </option>
                ))}
              </select>
            </Field>
            <Field name="asset-label" label="A name you recognize">
              <input
                id="asset-label"
                name="label"
                defaultValue={editing?.label ?? ""}
                placeholder="e.g. Primary email"
                maxLength={100}
                required
                autoFocus
              />
            </Field>
            <Field
              name="asset-value"
              label={
                kind === "email" ? "Email address" : "Identifier (optional)"
              }
              hint="Use the minimum information needed. Never enter a password, account number, or ID-document number."
            >
              <input
                id="asset-value"
                name="value"
                defaultValue={editing?.value ?? ""}
                type={kind === "email" ? "email" : "text"}
                maxLength={254}
                required={kind === "email" && !editing}
                placeholder={
                  kind === "email" ? "you@example.com" : "e.g. Personal MacBook"
                }
              />
            </Field>
            <label className="checkbox-label">
              <input
                name="critical"
                type="checkbox"
                defaultChecked={editing?.critical ?? true}
              />
              This is an important asset
            </label>
            {data.workspace.assets.length > 0 && (
              <fieldset>
                <legend>What can recover this asset?</legend>
                <p className="field-hint">
                  Choose existing accounts or devices used for recovery.
                </p>
                {data.workspace.assets
                  .filter((a) => a.id !== editing?.id)
                  .map((a) => (
                    <label key={a.id} className="checkbox-label">
                      <input
                        name="recovery"
                        type="checkbox"
                        value={a.id}
                        defaultChecked={
                          editing?.recoveryAssetIds?.includes(a.id) ?? false
                        }
                      />
                      {a.label}
                    </label>
                  ))}
              </fieldset>
            )}
            <ErrorMessage error={error} />
            <button type="submit" className="button primary" disabled={pending}>
              {pending ? "Saving…" : editing ? "Save changes" : "Add asset"}
              <PlusIcon />
            </button>
          </form>
        </Modal>
      )}
      {removing && (
        <Modal title="Remove this asset?" onClose={() => setRemoving(null)}>
          <div className="modal-form">
            <p>
              This removes the asset from your current checklist and its current
              evidence context. Existing audit snapshots remain in history.
            </p>
            <ErrorMessage error={error} />
            <div className="row">
              <button
                type="button"
                className="button secondary"
                onClick={() => setRemoving(null)}
              >
                Keep asset
              </button>
              <button
                type="button"
                className="button primary danger"
                disabled={pending}
                onClick={remove}
              >
                Remove asset
              </button>
            </div>
          </div>
        </Modal>
      )}
    </>
  );
}
export function History() {
  const { data, mutate, pending, notify } = useAudit();
  const [error, setError] = useState<unknown>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  if (!data) return null;
  const snapshots = [...data.workspace.snapshots].reverse();
  const snapshot = snapshots.find((s) => s.id === selected);
  async function audit() {
    try {
      await mutate("/audits", {});
      notify("Audit snapshot saved.");
    } catch (e) {
      setError(e);
    }
  }
  return (
    <>
      <PageHeading
        eyebrow="Your progress, preserved"
        title="Audit history"
        description="Compare past audits and keep a record of your progress."
        action={
          <button
            type="button"
            className="button primary"
            disabled={pending}
            onClick={audit}
          >
            <ArrowPathIcon />
            {pending ? "Saving…" : "Save a new audit"}
          </button>
        }
      />
      <ErrorMessage error={error} />
      {snapshots.length ? (
        <>
          <div className="history-summary">
            <div>
              <p className="metric-label">Saved audits</p>
              <p className="big-number">{snapshots.length}</p>
            </div>
            <div>
              <p className="metric-label">Latest posture</p>
              <p className="big-number">
                {snapshots[0]?.evaluation.score ?? "—"}
                <span>/100</span>
              </p>
            </div>
            <div>
              <p className="metric-label">Latest coverage</p>
              <p className="big-number">
                {snapshots[0]?.evaluation.coverage ?? 0}
                <span>%</span>
              </p>
            </div>
          </div>
          <div className="history-list">
            {snapshots.map((s, i) => {
              const previous = snapshots[i + 1];
              const delta =
                previous &&
                s.evaluation.score !== null &&
                previous.evaluation.score !== null
                  ? s.evaluation.score - previous.evaluation.score
                  : null;
              return (
                <button
                  type="button"
                  className="history-row"
                  key={s.id}
                  onClick={() => {
                    setSelected(s.id);
                    setConfirmDelete(false);
                  }}
                >
                  <div>
                    <p className="eyebrow">
                      {i === 0
                        ? "Latest snapshot"
                        : `Audit ${snapshots.length - i}`}
                    </p>
                    <h3>
                      {date(s.createdAt)}
                      <span className="history-time">
                        {new Date(s.createdAt).toLocaleTimeString(undefined, {
                          hour: "2-digit",
                          minute: "2-digit",
                        })}
                      </span>
                    </h3>
                    <p>
                      {s.assetIds.length} assets · {s.evidenceIds.length}{" "}
                      evidence records
                    </p>
                  </div>
                  <div className="history-score">
                    <strong>{s.evaluation.score ?? "—"}</strong>
                    <p>{s.evaluation.coverage}% assessed</p>
                  </div>
                  <div className="history-delta">
                    {delta === null
                      ? previous
                        ? "Not comparable"
                        : "First audit"
                      : `${delta > 0 ? "+" : ""}${delta} points`}
                  </div>
                  <ChevronRightIcon />
                </button>
              );
            })}
          </div>
        </>
      ) : (
        <EmptyState
          title="Your next chapter starts here"
          description="Save your first audit to begin a durable record of your security progress. Re-auditing preserves a snapshot; it does not replace verification."
        />
      )}
      {snapshot && (
        <Modal
          title={`Audit from ${date(snapshot.createdAt)}`}
          onClose={() => setSelected(null)}
        >
          <div className="modal-form">
            {confirmDelete ? (
              <>
                <h3>Delete this saved snapshot?</h3>
                <p>
                  Your current evidence, assets, and other snapshots stay
                  intact. Download a copy first if you want to preserve this
                  moment.
                </p>
                <ErrorMessage error={error} />
                <div className="row">
                  <button
                    type="button"
                    className="button secondary"
                    onClick={() => setConfirmDelete(false)}
                  >
                    Keep snapshot
                  </button>
                  <button
                    type="button"
                    className="button primary danger"
                    disabled={pending}
                    onClick={async () => {
                      try {
                        await mutate(
                          `/audits/${snapshot.id}`,
                          { confirmation: "DELETE" },
                          "DELETE",
                        );
                        setSelected(null);
                        setConfirmDelete(false);
                        notify(
                          "Snapshot deleted. Your current audit evidence is unchanged.",
                        );
                      } catch (e) {
                        setError(e);
                      }
                    }}
                  >
                    Delete snapshot
                  </button>
                </div>
              </>
            ) : (
              <>
                <ScoreRing
                  score={snapshot.evaluation.score}
                  coverage={snapshot.evaluation.coverage}
                  small
                />
                <p>
                  {snapshot.evaluation.coverage}% assessment coverage ·{" "}
                  {snapshot.assetIds.length} assets.
                </p>
                {CATEGORIES.map((c) => (
                  <div className="subject-row" key={c.id}>
                    <span>{c.name}</span>
                    <strong>
                      {snapshot.evaluation.categories.find(
                        (r) => r.categoryId === c.id,
                      )?.score ?? "—"}
                      /100
                    </strong>
                  </div>
                ))}
                <p className="field-hint">
                  Catalog {snapshot.evaluation.catalogVersion} · Scoring{" "}
                  {snapshot.evaluation.scoreVersion}
                </p>
                <button
                  type="button"
                  className="button secondary"
                  onClick={() => {
                    const url = URL.createObjectURL(
                      new Blob([JSON.stringify(snapshot, null, 2)], {
                        type: "application/json",
                      }),
                    );
                    const a = document.createElement("a");
                    a.href = url;
                    a.download = `palisade-snapshot-${snapshot.id}.json`;
                    a.click();
                    URL.revokeObjectURL(url);
                  }}
                >
                  <ArrowDownTrayIcon />
                  Download this snapshot
                </button>
                <button
                  type="button"
                  className="button ghost"
                  onClick={() => setConfirmDelete(true)}
                >
                  Delete this snapshot
                </button>
              </>
            )}
          </div>
        </Modal>
      )}
    </>
  );
}
