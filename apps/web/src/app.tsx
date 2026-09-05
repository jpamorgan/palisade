import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
} from "react";
import {
  Link,
  Navigate,
  Route,
  Routes,
  useLocation,
  useNavigate,
  useParams,
} from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowUpRightIcon,
  CheckIcon,
  ChevronDownIcon,
  DocumentDuplicateIcon,
  MinusIcon,
} from "@heroicons/react/16/solid";
import {
  CATEGORIES,
  CHECKS,
  type CheckResult,
  type CheckStatus,
  type Evaluation,
  type Workspace,
} from "@palisade/core";
import { z } from "zod";
import { buildAgentPrompt } from "./agent-prompt";
import {
  BootstrapSchema,
  ScanError,
  ScanStateSchema,
  copyText,
  forgetScan,
  latestScan,
  loadScan,
  privateScanPath,
  readCapability,
  refreshAgent,
  safeSourceUrl,
  saveScan,
  scanRequest,
  type BootstrapScan,
  type ScanState,
} from "./scan-client";

const categoryNames: Record<string, string> = {
  exposure: "Public exposure",
  accounts: "Accounts & sign-in",
  recovery: "Recovery & phone",
  devices: "Devices & browsers",
  network: "Home network",
  finance: "Money & identity",
  data: "Data & backups",
  response: "Monitoring & response",
};
const statusLabels: Record<CheckStatus, string> = {
  pass: "Verified",
  partial: "Partly protected",
  fail: "Needs attention",
  unknown: "Not checked",
  stale: "Recheck needed",
  conflict: "Needs verification",
  imported: "Needs verification",
  not_applicable: "Not applicable",
};
const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
const needsAttention = (check: CheckResult) =>
  ["fail", "partial", "conflict"].includes(check.status);

function Brand() {
  return (
    <Link to="/" className="brand" aria-label="Palisade homepage">
      palisade<span aria-hidden="true">.</span>
    </Link>
  );
}
function Header({ scan = false }: { scan?: boolean }) {
  return (
    <header className="site-header">
      <Brand />
      {scan && <span className="private-label">Private scan</span>}
    </header>
  );
}
function PromptFallback({
  prompt,
  children,
}: {
  prompt: string;
  children?: React.ReactNode;
}) {
  const field = useRef<HTMLTextAreaElement>(null);
  useEffect(() => {
    field.current?.focus();
    field.current?.select();
  }, []);
  return (
    <div
      className="prompt-fallback"
      role="region"
      aria-label="Copy your agent prompt"
    >
      <p>
        Automatic copy is unavailable. Copy this prompt, then paste it into your
        agent.
      </p>
      <label className="sr-only" htmlFor="agent-prompt">
        Private agent prompt
      </label>
      <textarea
        ref={field}
        id="agent-prompt"
        name="agent-prompt"
        readOnly
        value={prompt}
        spellCheck={false}
        onFocus={(event) => event.currentTarget.select()}
      />
      <p className="small muted">
        This prompt gives your agent access to this scan. Keep it private.
      </p>
      {children}
    </div>
  );
}

export function Landing() {
  const navigate = useNavigate();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [created, setCreated] = useState<BootstrapScan>();
  const [fallback, setFallback] = useState("");
  const [stored, setStored] = useState(true);
  const [previous] = useState(latestScan);
  const inFlight = useRef(false);
  useEffect(() => {
    document.title = "Palisade — Your personal security audit";
  }, []);
  async function start() {
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    setError("");
    try {
      const scan =
        created ??
        (await scanRequest("/api/scans", {
          method: "POST",
          body: {},
          schema: BootstrapSchema,
        }));
      setCreated(scan);
      const persisted = saveScan(scan);
      setStored(persisted);
      const prompt = buildAgentPrompt(scan, "start");
      if (await copyText(prompt))
        navigate(privateScanPath(scan), {
          state: { promptCopied: true, temporary: !persisted },
        });
      else setFallback(prompt);
    } catch (error) {
      setError(
        error instanceof Error
          ? error.message
          : "Couldn’t start your scan. Please try again.",
      );
    } finally {
      setBusy(false);
      inFlight.current = false;
    }
  }
  return (
    <div className="site landing-page">
      <Header />
      <main id="main-content" className="landing-main" tabIndex={-1}>
        <p className="eyebrow">Personal security, with your agent.</p>
        <h1>
          Find your risks.
          <br />
          Close the gaps.
        </h1>
        <p className="hero-description">
          Your agent checks your accounts, devices, and public exposure, then
          fixes what it safely can. Follow your audit live.
        </p>
        <div className="hero-action">
          <button
            type="button"
            className="button primary"
            onClick={start}
            disabled={busy}
            aria-busy={busy}
          >
            <DocumentDuplicateIcon />
            {busy ? "Preparing your prompt…" : "Copy agent prompt"}
          </button>
          <p>Paste into Codex, Claude, or your agent.</p>
        </div>
        {error && (
          <p className="error-message" role="alert">
            {error}
          </p>
        )}
        {fallback && created && (
          <PromptFallback prompt={fallback}>
            <Link
              className="text-link"
              to={privateScanPath(created)}
              state={{ temporary: !stored }}
            >
              Open my scan <ArrowUpRightIcon />
            </Link>
          </PromptFallback>
        )}
      </main>
      <footer className="landing-footer">
        <span>No account needed. Your scan is private.</span>
        {previous ? (
          <Link to={privateScanPath(previous)}>
            Return to your scan <ArrowUpRightIcon />
          </Link>
        ) : (
          <a
            href="https://github.com/jpamorgan/palisade"
            target="_blank"
            rel="noreferrer"
          >
            Open source <ArrowUpRightIcon />
          </a>
        )}
      </footer>
    </div>
  );
}

function ScanMessage({
  state,
  reconnecting,
  stale,
}: {
  state: ScanState;
  reconnecting: boolean;
  stale: boolean;
}) {
  const status = state.scan.status;
  const label = reconnecting
    ? "Reconnecting"
    : stale
      ? "Waiting for your agent"
      : {
          waiting: "Ready for your agent",
          running: "Audit in progress",
          waiting_for_user: "Your agent needs you",
          blocked: "Your agent needs help",
          complete: state.target?.met
            ? "Target reached"
            : "Pass complete · gaps remain",
        }[status];
  const message = reconnecting
    ? "Your last results are shown below. We’re trying to reconnect."
    : stale
      ? "No recent update. Check your agent conversation for a permission request or resume the audit there."
      : status === "waiting"
        ? "Paste the prompt into your agent. Your results will appear here as it works."
        : state.scan.message;
  return (
    <div className="scan-message" aria-live="polite" aria-atomic="true">
      <p
        className={`run-status ${status === "running" && !reconnecting && !stale ? "is-running" : ""} ${status === "complete" && !state.target?.met ? "has-gaps" : ""}`}
      >
        <span className="status-dot" aria-hidden="true" />
        {label}
      </p>
      <h1>Your security audit.</h1>
      <p className="scan-description">
        {message ||
          "Your agent is reviewing the evidence and working through your next steps."}
      </p>
    </div>
  );
}
export function ScanResults({ state }: { state: ScanState }) {
  const { evaluation, workspace } = state;
  const applicableChecks = evaluation.checks.filter(
    (check) => check.status !== "not_applicable",
  );
  const assessed = applicableChecks.filter((check) => check.assessed).length;
  const urgent = evaluation.checks.filter(needsAttention);
  const criticalCount =
    state.target?.criticalGaps ??
    evaluation.findings.filter((finding) => finding.severity === "critical")
      .length;
  const categoryPriority = (categoryId: string) =>
    Math.min(
      4,
      ...evaluation.findings
        .filter(
          (finding) =>
            finding.kind !== "verification" &&
            CHECKS.find((check) => check.id === finding.checkId)?.categoryId ===
              categoryId,
        )
        .map((finding) => severityOrder[finding.severity]),
    );
  return (
    <>
      <section className="score-section" aria-label="Live security assessment">
        <div className="score-number">
          <div className="metric-label">Security score</div>
          <p
            aria-label={
              evaluation.score === null
                ? "Not scored yet"
                : `${evaluation.score} out of 100`
            }
          >
            <strong>{evaluation.score ?? "—"}</strong>
            <span>/ 100</span>
          </p>
        </div>
        <div className="coverage-metric">
          <div className="coverage-label">
            <strong>{evaluation.coverage}% assessed</strong>
            <span>
              {applicableChecks.length === 0
                ? "No applicable checks"
                : `${assessed} of ${applicableChecks.length} checks`}
            </span>
          </div>
          <div
            className="progress"
            role="progressbar"
            aria-label="Assessment coverage"
            aria-valuenow={evaluation.coverage}
            aria-valuemin={0}
            aria-valuemax={100}
          >
            <span
              style={
                { "--progress": `${evaluation.coverage}%` } as CSSProperties
              }
            />
          </div>
          <p>
            {evaluation.score === null
              ? "Your score appears when evidence arrives."
              : state.target?.met
                ? "Your current evidence meets the audit target."
                : "Target 85 · 90% assessed"}
          </p>
        </div>
      </section>
      <div className="results-heading">
        <h2>Your results</h2>
        <p>
          {criticalCount > 0
            ? `${criticalCount} critical ${criticalCount === 1 ? "gap" : "gaps"}`
            : urgent.length > 0
              ? `${urgent.length} ${urgent.length === 1 ? "check needs" : "checks need"} attention`
              : state.scan.status === "complete"
                ? `${assessed} ${assessed === 1 ? "check" : "checks"} assessed`
                : assessed === 0
                  ? "Waiting for evidence"
                  : "Updates as your agent works"}
        </p>
      </div>
      <section className="results-list" aria-label="Results by security area">
        {CATEGORIES.slice()
          .sort((a, b) => categoryPriority(a.id) - categoryPriority(b.id))
          .map((category) => {
            const checks = evaluation.checks.filter(
              (check) =>
                CHECKS.find((definition) => definition.id === check.checkId)
                  ?.categoryId === category.id,
            );
            const applicable = checks.filter(
              (check) => check.status !== "not_applicable",
            );
            const done = applicable.filter((check) => check.assessed).length;
            const attention = checks.filter(needsAttention).length;
            const verified = checks.filter(
              (check) => check.status === "pass",
            ).length;
            const categoryResult = evaluation.categories.find(
              (item) => item.categoryId === category.id,
            );
            const priority = checks
              .filter(needsAttention)
              .sort(
                (a, b) =>
                  severityOrder[
                    CHECKS.find((item) => item.id === a.checkId)!.severity
                  ] -
                  severityOrder[
                    CHECKS.find((item) => item.id === b.checkId)!.severity
                  ],
              )[0];
            const dependency = evaluation.findings.find(
              (finding) =>
                finding.kind === "dependency" &&
                CHECKS.find((check) => check.id === finding.checkId)
                  ?.categoryId === category.id,
            );
            return (
              <details
                className="category"
                key={category.id}
                data-attention={Boolean(priority || dependency)}
              >
                <summary>
                  <div className="category-name">
                    <span>{categoryNames[category.id]}</span>
                    <span className="category-meta">
                      {dependency
                        ? dependency.title
                        : priority
                          ? `${CHECKS.find((check) => check.id === priority.checkId)!.title}${attention > 1 ? ` · +${attention - 1} more` : ""}`
                          : applicable.length === 0
                            ? "Not applicable"
                            : done === 0
                              ? "Not checked yet"
                              : verified === applicable.length
                                ? "All checks verified"
                                : `${done} of ${applicable.length} checked`}
                    </span>
                  </div>
                  <div
                    className="category-progress"
                    aria-label={`${categoryNames[category.id]}: ${categoryResult?.coverage ?? 0}% assessed`}
                  >
                    <div
                      className={`mini-progress ${attention ? "has-gaps" : ""}`}
                    >
                      <span
                        style={
                          {
                            "--progress": `${categoryResult?.coverage ?? 0}%`,
                          } as CSSProperties
                        }
                      />
                    </div>
                    <span>
                      {applicable.length === 0
                        ? "—"
                        : `${done}/${applicable.length}`}
                    </span>
                  </div>
                  <ChevronDownIcon className="chevron" />
                </summary>
                <div className="category-content">
                  {evaluation.findings
                    .filter(
                      (finding) =>
                        finding.kind === "dependency" &&
                        CHECKS.find((check) => check.id === finding.checkId)
                          ?.categoryId === category.id,
                    )
                    .map((finding) => (
                      <div className="dependency-finding" key={finding.id}>
                        <h3>{finding.title}</h3>
                        <p>{finding.description}</p>
                        <p>{finding.action}</p>
                      </div>
                    ))}
                  {checks
                    .slice()
                    .sort(
                      (a, b) =>
                        Number(needsAttention(b)) - Number(needsAttention(a)) ||
                        severityOrder[
                          CHECKS.find((check) => check.id === a.checkId)!
                            .severity
                        ] -
                          severityOrder[
                            CHECKS.find((check) => check.id === b.checkId)!
                              .severity
                          ],
                    )
                    .map((check) => (
                      <CheckDetail
                        key={check.checkId}
                        result={check}
                        workspace={workspace}
                      />
                    ))}
                </div>
              </details>
            );
          })}
      </section>
      {workspace.threatEvents.length > 0 && (
        <details className="research-disclosure">
          <summary>
            Sources & research <span>{workspace.threatEvents.length}</span>
            <ChevronDownIcon className="chevron" />
          </summary>
          <p className="muted">
            Public research adds context. It is not evidence that your
            information was compromised.
          </p>
          <ul className="research-list" role="list">
            {workspace.threatEvents
              .slice()
              .reverse()
              .map((event) => (
                <li key={event.id}>
                  <p>
                    {safeSourceUrl(event.url) ? (
                      <a
                        href={safeSourceUrl(event.url)}
                        target="_blank"
                        rel="noreferrer"
                      >
                        {event.title}
                        <ArrowUpRightIcon />
                      </a>
                    ) : (
                      event.title
                    )}
                  </p>
                  <p className="small muted">{event.description}</p>
                </li>
              ))}
          </ul>
        </details>
      )}
    </>
  );
}

function CheckDetail({
  result,
  workspace,
}: {
  result: Evaluation["checks"][number];
  workspace: Workspace;
}) {
  const definition = CHECKS.find((check) => check.id === result.checkId);
  if (!definition) return null;
  const observed = result.subjects.map((subject) => ({
    subject,
    evidence: workspace.evidence.find((item) => item.id === subject.evidenceId),
  }));
  return (
    <details className="check-detail">
      <summary>
        <span className={`check-symbol ${result.status}`} aria-hidden="true">
          {result.status === "pass" ? (
            <CheckIcon />
          ) : result.status === "not_applicable" ? (
            <MinusIcon />
          ) : result.status === "fail" || result.status === "partial" ? (
            "!"
          ) : (
            "·"
          )}
        </span>
        <span className="check-title">{definition.title}</span>
        <span className={`check-status ${result.status}`}>
          {statusLabels[result.status]}
        </span>
        <ChevronDownIcon className="chevron" />
      </summary>
      <div className="check-content">
        <p>{definition.description}</p>
        {observed.map(({ subject, evidence }, index) => (
          <div className="observation" key={subject.assetId ?? index}>
            {subject.assetId && (
              <p className="observation-label">
                {workspace.assets.find((asset) => asset.id === subject.assetId)
                  ?.label ?? "Audited item"}{" "}
                <span>{statusLabels[subject.status]}</span>
              </p>
            )}
            <p>{evidence?.notes || subject.reason}</p>
            {evidence && (
              <p className="small muted">
                Observed {formatDate(evidence.observedAt)}
                {evidence.facts?.source_label
                  ? ` · ${String(evidence.facts.source_label)}`
                  : ""}
              </p>
            )}
            {safeSourceUrl(evidence?.facts?.source_url) && (
              <a
                className="text-link small"
                href={safeSourceUrl(evidence?.facts?.source_url)}
                target="_blank"
                rel="noreferrer"
              >
                View source <ArrowUpRightIcon />
              </a>
            )}
          </div>
        ))}
        {result.status !== "pass" && result.status !== "not_applicable" && (
          <div className="next-step">
            <h3>
              {needsAttention(result)
                ? "What to do next"
                : "What your agent will verify"}
            </h3>
            <p>
              {needsAttention(result)
                ? definition.remediation.title
                : definition.verification}
            </p>
            {needsAttention(result) && (
              <ol>
                {definition.remediation.steps.map((step) => (
                  <li key={step}>{step}</li>
                ))}
              </ol>
            )}
            <p className="small muted">
              Continue in your agent conversation. A fix counts only after it is
              verified.
            </p>
          </div>
        )}
      </div>
    </details>
  );
}
function formatDate(value: string) {
  const date = new Date(value);
  return Number.isFinite(date.getTime())
    ? date.toLocaleDateString(undefined, {
        month: "short",
        day: "numeric",
        year: "numeric",
      })
    : "date unavailable";
}

export function ScanPage() {
  const { id = "" } = useParams();
  const location = useLocation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [owner, setOwner] = useState(() => loadScan(id));
  const [copyBusy, setCopyBusy] = useState(false);
  const [copied, setCopied] = useState(Boolean(location.state?.promptCopied));
  const [prompt, setPrompt] = useState("");
  const [actionError, setActionError] = useState("");
  const [deleting, setDeleting] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const readToken = readCapability(location.hash) ?? owner?.readToken;
  const queryKey = useMemo(() => ["scan", id, readToken], [id, readToken]);
  const query = useQuery({
    queryKey,
    queryFn: ({ signal }) =>
      scanRequest(`/api/scans/${encodeURIComponent(id)}`, {
        token: readToken,
        schema: ScanStateSchema,
        signal,
      }),
    enabled: Boolean(readToken),
    retry: (count, error) =>
      !(error instanceof ScanError && error.terminal) && count < 1,
    refetchInterval: (query) =>
      query.state.error instanceof ScanError && query.state.error.terminal
        ? false
        : 2_000,
    refetchIntervalInBackground: false,
    refetchOnWindowFocus: true,
    staleTime: 1_000,
  });
  useEffect(() => {
    document.title = "Your security scan — Palisade";
  }, []);
  useEffect(() => {
    if (!copied) return;
    const timer = setTimeout(() => setCopied(false), 3_000);
    return () => clearTimeout(timer);
  }, [copied]);
  async function continueAudit() {
    if (!owner || copyBusy) return;
    setCopyBusy(true);
    setActionError("");
    try {
      const current = await refreshAgent(owner);
      setOwner(current);
      const text = buildAgentPrompt(
        current,
        query.data?.scan.status === "waiting" ? "start" : "continue",
      );
      if (await copyText(text)) {
        setCopied(true);
        setPrompt("");
      } else setPrompt(text);
    } catch (error) {
      setActionError(
        error instanceof Error
          ? error.message
          : "Couldn’t prepare your prompt. Please try again.",
      );
    } finally {
      setCopyBusy(false);
    }
  }
  async function deleteScan() {
    if (!owner || deleting) return;
    setDeleting(true);
    setActionError("");
    try {
      await scanRequest(`/api/scans/${id}`, {
        method: "DELETE",
        token: owner.ownerToken,
        body: { confirmation: "DELETE" },
        schema: z.unknown(),
      });
      forgetScan(id);
      queryClient.removeQueries({ queryKey });
      navigate("/", { replace: true });
    } catch (error) {
      setActionError(
        error instanceof Error
          ? error.message
          : "Couldn’t delete your scan. Please try again.",
      );
      setDeleting(false);
    }
  }
  const terminalError =
    query.error instanceof ScanError && query.error.terminal;
  const data = terminalError ? undefined : query.data;
  const stale =
    data?.scan.status === "running" &&
    Date.now() - Date.parse(data.scan.updatedAt) > 120_000;
  return (
    <div className="site scan-page">
      <Header scan />
      <main id="main-content" className="scan-main" tabIndex={-1}>
        {!readToken || terminalError ? (
          <div className="unavailable">
            <h1>This scan isn’t available.</h1>
            <p>
              {readToken
                ? query.error?.message
                : "Open the original private link from your agent conversation to view this scan."}
            </p>
            <Link to="/" className="button primary">
              Start a new audit
            </Link>
          </div>
        ) : !data ? (
          <div className="unavailable" role="status">
            <h1>
              {query.isError
                ? "Couldn’t load your scan."
                : "Opening your scan…"}
            </h1>
            <p>
              {query.isError
                ? query.error.message
                : "Retrieving your latest results."}
            </p>
            {query.isError && (
              <button
                type="button"
                className="button primary"
                onClick={() => query.refetch()}
              >
                Try again
              </button>
            )}
          </div>
        ) : (
          <>
            <ScanMessage
              state={data}
              reconnecting={query.isError}
              stale={Boolean(stale)}
            />
            {location.state?.temporary && (
              <p className="notice">
                This browser blocked saving your access. Keep this tab open to
                continue or delete the scan.
              </p>
            )}
            {(data.scan.status === "waiting" ||
              data.scan.status === "waiting_for_user" ||
              data.scan.status === "blocked" ||
              data.scan.status === "complete" ||
              stale) && (
              <div className="scan-action">
                {owner ? (
                  <>
                    <button
                      type="button"
                      className="button primary compact"
                      onClick={continueAudit}
                      disabled={copyBusy}
                      aria-busy={copyBusy}
                    >
                      {copied ? <CheckIcon /> : <DocumentDuplicateIcon />}
                      {copyBusy
                        ? "Preparing prompt…"
                        : copied
                          ? "Prompt copied"
                          : data.scan.status === "waiting"
                            ? "Copy prompt again"
                            : "Copy continuation prompt"}
                    </button>
                    <p>
                      {data.scan.status === "waiting"
                        ? "Then paste it into your agent to begin."
                        : "Paste into your agent to keep going."}
                    </p>
                  </>
                ) : (
                  <p className="muted">
                    Continue in your original agent conversation to work through
                    the remaining checks.
                  </p>
                )}
              </div>
            )}
            {copied && (
              <span className="sr-only" role="status">
                Prompt copied. Paste it into your agent.
              </span>
            )}
            {actionError && (
              <p className="error-message" role="alert">
                {actionError}
              </p>
            )}
            {prompt && <PromptFallback prompt={prompt} />}
            <ScanResults state={data} />
            <details className="scoring-note">
              <summary>
                How your score works <ChevronDownIcon className="chevron" />
              </summary>
              <p>
                Your score uses the same versioned rules for every audit.
                Coverage shows how much has been assessed; unchecked items never
                count as protected. Your agent reports observations, and
                Palisade calculates the score.
              </p>
              <p>
                The target is a score of at least 85, at least 90% assessment
                coverage, and no critical gaps. A score is a measure of checked
                protections, not a guarantee against an attack. Completed fixes
                must be verified before they improve it.
              </p>
              <p className="small muted">
                Scoring {data.evaluation.scoreVersion} · Catalog{" "}
                {data.evaluation.catalogVersion}
              </p>
            </details>
            <footer className="scan-footer">
              <p>
                Keep this link private. Available until{" "}
                {formatDate(data.scan.expiresAt)}.
              </p>
              {owner && (
                <button
                  type="button"
                  className="quiet-button"
                  onClick={() => setConfirmDelete((value) => !value)}
                >
                  Delete scan
                </button>
              )}
            </footer>
            {confirmDelete && owner && (
              <div
                className="delete-confirmation"
                role="region"
                aria-label="Delete this scan"
              >
                <p>
                  Delete this scan and all its results? This cannot be undone.
                </p>
                <div>
                  <button
                    type="button"
                    className="button destructive compact"
                    onClick={deleteScan}
                    disabled={deleting}
                  >
                    {deleting ? "Deleting…" : "Delete permanently"}
                  </button>
                  <button
                    type="button"
                    className="quiet-button"
                    onClick={() => setConfirmDelete(false)}
                    disabled={deleting}
                  >
                    Keep scan
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </main>
    </div>
  );
}
export function AppRoutes() {
  return (
    <>
      <a
        className="skip-link"
        href="#main-content"
        onClick={(event) => {
          event.preventDefault();
          const main = document.getElementById("main-content");
          main?.focus();
          main?.scrollIntoView();
        }}
      >
        Skip to content
      </a>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/scan/:id" element={<ScanRoute />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </>
  );
}
function ScanRoute() {
  const { id } = useParams();
  return <ScanPage key={id} />;
}
