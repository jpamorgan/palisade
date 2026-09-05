import { useState, useRef, type FormEvent, useEffect } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  ArrowRightIcon,
  ArrowPathIcon,
  ArrowDownTrayIcon,
  ArrowUpTrayIcon,
  PlusIcon,
  KeyIcon,
  CheckCircleIcon,
} from "@heroicons/react/16/solid";
import { authClient } from "./auth";
import {
  api,
  useAudit,
  date,
  downloadWorkspace,
  auditKeys,
  auditHref,
  readWorkspaceImport,
} from "./data";
import { PageHeading, ErrorMessage, Field, EmptyState, Modal } from "./ui";
interface Integrations {
  hibp: { configured: boolean };
  brave?: { configured: boolean };
  publicFeeds: { available: boolean };
  monitoring: { enabled: boolean };
  emailVerification: { available: boolean };
}
interface Token {
  id: string;
  name: string;
  prefix: string;
  scopes: string[];
  createdAt: string;
  expiresAt: string;
  lastUsedAt: string | null;
}
export function Exposure() {
  const { data, base, demo, mutate, pending, notify, userId } = useAudit();
  const [params] = useSearchParams();
  const { data: integrations } = useQuery({
    queryKey: auditKeys.integrations(userId),
    queryFn: () => api<Integrations>("/integrations"),
    enabled: !demo,
  });
  const [assetId, setAssetId] = useState(params.get("asset") ?? "");
  const [footprintAsset, setFootprintAsset] = useState("");
  const [consent, setConsent] = useState(false);
  const [searchConsent, setSearchConsent] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [receipt, setReceipt] = useState<{
    status: string;
    message: string;
  } | null>(null);
  if (!data) return null;
  const emails = data.workspace.assets.filter(
    (a) => a.kind === "email" && a.value,
  );
  const searchAssets = data.workspace.assets.filter(
    (a) =>
      ["email", "domain", "identity"].includes(a.kind) &&
      (a.value || a.kind === "identity"),
  );
  async function scan(kind: "hibp" | "threats" | "footprint") {
    setError(null);
    setReceipt(null);
    try {
      const body =
        kind === "hibp"
          ? { assetId: assetId || emails[0]?.id, consent: true }
          : kind === "footprint"
            ? { assetId: footprintAsset || searchAssets[0]?.id, consent: true }
            : {};
      const result = await mutate<any>(`/scans/${kind}`, body);
      setReceipt(
        result.receipt ?? {
          status: "ok",
          message: "Scan complete. Review the collected events below.",
        },
      );
    } catch (e) {
      setError(e);
    }
  }
  return (
    <>
      <PageHeading
        eyebrow="Context for your checklist"
        title="Exposure checks"
        description="Check known breaches, public search matches, and current threat reports."
        action={
          <button
            type="button"
            className="button secondary"
            onClick={() => scan("threats")}
            disabled={pending}
          >
            <ArrowPathIcon />
            {pending ? "Checking…" : "Refresh public threats"}
          </button>
        }
      />
      <ErrorMessage error={error} />
      {receipt && (
        <div
          className={`scan-receipt ${receipt.status === "ok" ? "success" : "warning"}`}
          role="status"
        >
          <strong>
            {receipt.status === "ok"
              ? "Scan completed"
              : receipt.status === "unavailable"
                ? "Provider unavailable"
                : "Scan could not complete"}
          </strong>
          <p>{receipt.message}</p>
        </div>
      )}
      <div className="scan-grid">
        <section className="integration-card">
          <div className="integration-heading">
            <h2>Known breach exposure</h2>
            <span className="quiet-badge">Have I Been Pwned</span>
          </div>
          <p>
            Look for known breaches associated with an email you own. Historical
            exposure remains in your record after you improve your protections.
          </p>
          {!demo && !integrations?.hibp.configured ? (
            <Link
              to={`${auditHref(base, { panel: "settings" })}#integrations`}
              className="text-link"
            >
              Connect your HIBP API key <ArrowRightIcon />
            </Link>
          ) : null}
          <Field name="scan-email" label="Email to check">
            <select
              id="scan-email"
              name="scan-email"
              value={assetId || emails[0]?.id || ""}
              onChange={(e) => setAssetId(e.target.value)}
            >
              {emails.length ? (
                emails.map((a) => (
                  <option value={a.id} key={a.id}>
                    {a.label} · {a.value}
                  </option>
                ))
              ) : (
                <option value="">Add an email asset first</option>
              )}
            </select>
          </Field>
          <label className="checkbox-label">
            <input
              type="checkbox"
              name="hibp-consent"
              checked={consent}
              onChange={(e) => setConsent(e.target.checked)}
            />
            I own this email and consent to sending it to Have I Been Pwned.
          </label>
          <p className="field-hint">
            The hosted service currently checks your verified sign-in email.
            Email verification must be available before a scan can run.
          </p>
          <button
            type="button"
            className="button primary"
            disabled={
              pending ||
              !consent ||
              !emails.length ||
              (!demo && !integrations?.hibp.configured)
            }
            onClick={() => scan("hibp")}
          >
            Check breach exposure <ArrowRightIcon />
          </button>
        </section>
        <section className="integration-card">
          <div className="integration-heading">
            <h2>Your public footprint</h2>
            <span className="quiet-badge">Brave Search</span>
          </div>
          <p>
            Search for a specific public identifier. Review each result for
            relevance and identity matches before drawing conclusions.
          </p>
          {!demo && !integrations?.brave?.configured ? (
            <Link
              to={`${auditHref(base, { panel: "settings" })}#integrations`}
              className="text-link"
            >
              Connect your Brave API key <ArrowRightIcon />
            </Link>
          ) : null}
          <Field name="footprint-asset" label="Identifier to search">
            <select
              id="footprint-asset"
              name="footprint-asset"
              value={footprintAsset || searchAssets[0]?.id || ""}
              onChange={(e) => setFootprintAsset(e.target.value)}
            >
              {searchAssets.length ? (
                searchAssets.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.label}
                    {a.value ? ` · ${a.value}` : ""}
                  </option>
                ))
              ) : (
                <option value="">
                  Add an email, domain, or identity asset
                </option>
              )}
            </select>
          </Field>
          <label className="checkbox-label">
            <input
              type="checkbox"
              name="search-consent"
              checked={searchConsent}
              onChange={(e) => setSearchConsent(e.target.checked)}
            />
            This identifier is mine and I consent to sending it to Brave Search.
          </label>
          <p className="field-hint">
            Search results are possible matches, not proof of targeting or
            compromise. Public prominence does not reduce your posture score.
          </p>
          <button
            type="button"
            className="button secondary"
            disabled={
              pending ||
              !searchConsent ||
              !searchAssets.length ||
              (!demo && !integrations?.brave?.configured)
            }
            onClick={() => scan("footprint")}
          >
            Search public footprint <ArrowRightIcon />
          </button>
        </section>
      </div>
      <section className="threat-section">
        <div className="section-top">
          <div>
            <h2>Exposure & threat records</h2>
            <p>
              Published information is context. Your own verification determines
              relevance.
            </p>
          </div>
          <span className="quiet-badge">
            {data.workspace.threatEvents.length} records
          </span>
        </div>
        {data.workspace.threatEvents.length ? (
          <div className="threat-list">
            {[...data.workspace.threatEvents].reverse().map((event) => (
              <article className="threat-row" key={event.id}>
                <div className="threat-meta">
                  <span>{event.source.toUpperCase()}</span>
                  <span>{date(event.publishedAt)}</span>
                  <span className="quiet-badge">
                    {event.relevance === "confirmed"
                      ? "Provider-confirmed exposure"
                      : event.relevance === "potential"
                        ? "Potential relevance"
                        : "Relevance not assessed"}
                  </span>
                </div>
                <h3>
                  <a href={event.url} target="_blank" rel="noreferrer">
                    {event.title}
                    <ArrowRightIcon />
                  </a>
                </h3>
                <p>{event.description}</p>
                {event.assetId && (
                  <p className="field-hint">
                    Related asset:{" "}
                    {data.workspace.assets.find((a) => a.id === event.assetId)
                      ?.label ?? "Removed asset"}
                  </p>
                )}
              </article>
            ))}
          </div>
        ) : (
          <EmptyState
            title="No exposure records yet"
            description="Connect a provider to check your own identifiers, or refresh public threats to review current context from public sources."
          />
        )}
      </section>
      <div className="verification-note">
        <h3>A reported leak is a reason to check.</h3>
        <p>
          It is not confirmation that your identity is in it. Use the exposure
          checklist to verify relevance and work through proportionate next
          steps.
        </p>
        <Link to={auditHref(base, { area: "exposure" })} className="text-link">
          Open exposure checks <ArrowRightIcon />
        </Link>
      </div>
    </>
  );
}
export function Settings() {
  const { data, demo, mutate, pending, notify, userId } = useAudit();
  const { data: session } = authClient.useSession();
  const { data: integrations, error: integrationError } = useQuery({
    queryKey: auditKeys.integrations(userId),
    queryFn: () => api<Integrations>("/integrations"),
    enabled: !demo,
  });
  const { data: tokenData, error: tokenError } = useQuery({
    queryKey: auditKeys.tokens(userId),
    queryFn: () => api<{ tokens: Token[] }>("/tokens"),
    enabled: !demo,
  });
  const [error, setError] = useState<unknown>(null);
  const [issued, setIssued] = useState("");
  const [creatingToken, setCreatingToken] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [confirmation, setConfirmation] = useState("");
  const [importFile, setImportFile] = useState<File | null>(null);
  const [importReady, setImportReady] = useState<unknown>(null);
  const [passkeys, setPasskeys] = useState<
    { id: string; name?: string | null; createdAt: Date }[]
  >([]);
  const [twoFactor, setTwoFactor] = useState<{
    totpURI: string;
    backupCodes: string[];
  } | null>(null);
  const [qr, setQr] = useState("");
  const [securityMessage, setSecurityMessage] = useState("");
  const [revoke, setRevoke] = useState<Token | null>(null);
  useEffect(() => {
    if (!demo)
      void authClient.passkey
        .listUserPasskeys()
        .then((r) => {
          if (r.data) setPasskeys(r.data);
        })
        .catch(() => {});
  }, [demo]);
  if (!data) return null;
  async function saveWorkspace(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    const f = new FormData(e.currentTarget);
    try {
      await mutate(
        "/workspace",
        {
          name: String(f.get("name")),
          settings: {
            ...data!.workspace.settings,
            region: String(f.get("region")),
            monitoring: f.get("monitoring") === "on",
          },
          revision: data!.revision,
        },
        "PATCH",
      );
      notify("Workspace preferences saved.");
    } catch (e) {
      setError(e);
    }
  }
  async function integration(e: FormEvent<HTMLFormElement>, provider: string) {
    e.preventDefault();
    setError(null);
    const form = e.currentTarget;
    try {
      await mutate(`/integrations/${provider}`, {
        apiKey: String(new FormData(form).get("apiKey")),
      });
      form.reset();
      notify("Integration connected. Your key is stored encrypted.");
    } catch (e) {
      setError(e);
    }
  }
  async function disconnect(provider: string) {
    setError(null);
    try {
      await mutate(`/integrations/${provider}`, undefined, "DELETE");
      notify("Integration disconnected.");
    } catch (e) {
      setError(e);
    }
  }
  async function issue(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    const f = new FormData(e.currentTarget);
    try {
      const result = await mutate<{ token: string }>("/tokens", {
        name: String(f.get("token-name")),
        scopes: f.getAll("scope"),
        expiresInDays: Number(f.get("expiry")),
      });
      setIssued(result.token);
      setCreatingToken(false);
    } catch (e) {
      setError(e);
    }
  }
  async function prepareImport(file: File | undefined) {
    setError(null);
    setImportFile(null);
    setImportReady(null);
    if (!file) return;
    try {
      const parsed = await readWorkspaceImport(file);
      setImportFile(file);
      setImportReady(parsed);
    } catch (e) {
      setError(e);
    }
  }
  async function importWorkspace() {
    try {
      await mutate("/imports", { workspace: importReady });
      setImportFile(null);
      setImportReady(null);
      notify(
        "Workspace imported. Imported observations earn no points until you verify them in this workspace.",
      );
    } catch (e) {
      setError(e);
    }
  }
  async function addPasskey() {
    setError(null);
    try {
      const r = await authClient.passkey.addPasskey({
        name: "Palisade passkey",
      });
      if (r.error) throw new Error(r.error.message);
      const keys = await authClient.passkey.listUserPasskeys();
      if (keys.data) setPasskeys(keys.data);
      notify("Passkey added to your account.");
    } catch (e) {
      setError(e);
    }
  }
  async function setup2FA(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    try {
      const r = await authClient.twoFactor.enable({
        password: String(new FormData(e.currentTarget).get("current-password")),
        issuer: "Palisade",
      });
      if (r.error) throw new Error(r.error.message);
      if (r.data?.method === "totp") {
        setTwoFactor(r.data);
        const QRCode = await import("qrcode");
        setQr(
          await QRCode.toDataURL(r.data.totpURI, { margin: 1, width: 192 }),
        );
      }
    } catch (e) {
      setError(e);
    }
  }
  async function confirm2FA(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    try {
      const r = await authClient.twoFactor.verifyTotp({
        code: String(new FormData(e.currentTarget).get("totp-code")),
      });
      if (r.error) throw new Error(r.error.message);
      setSecurityMessage(
        "Two-factor authentication enabled. Save your backup codes in your password manager before closing this section.",
      );
      await authClient.getSession({ query: { disableCookieCache: true } });
    } catch (e) {
      setError(e);
    }
  }
  async function disable2FA(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    try {
      const r = await authClient.twoFactor.disable({
        password: String(new FormData(e.currentTarget).get("disable-password")),
      });
      if (r.error) throw new Error(r.error.message);
      setSecurityMessage("Two-factor authentication disabled.");
      await authClient.getSession({ query: { disableCookieCache: true } });
    } catch (e) {
      setError(e);
    }
  }
  return (
    <>
      <PageHeading
        eyebrow="Your workspace, your controls"
        title="Settings"
        description="Manage integrations, protect your account, and decide how your audit travels."
      />
      <ErrorMessage error={error} />
      {demo && (
        <div className="verification-note">
          <h3>A demo with clear boundaries</h3>
          <p>
            You can edit the demo preferences and try import/export. Live
            integrations, account security, and access tokens require your own
            private workspace.
          </p>
          <Link to="/?auth=signup" className="text-link">
            Create a workspace <ArrowRightIcon />
          </Link>
        </div>
      )}
      <div className="settings-layout">
        <div className="settings-sections">
          <details id="workspace" className="settings-section" open>
            <summary>Workspace preferences</summary>
            <h2>Workspace preferences</h2>
            <p>
              Your region determines which protections are relevant to your
              checklist.
            </p>
            <form onSubmit={saveWorkspace}>
              <Field name="workspace-name" label="Workspace name">
                <input
                  id="workspace-name"
                  name="name"
                  defaultValue={data.workspace.name}
                  maxLength={100}
                  required
                />
              </Field>
              <Field name="region" label="Region">
                <select
                  id="region"
                  name="region"
                  defaultValue={data.workspace.settings.region}
                >
                  <option value="unspecified">Choose your region</option>
                  <option value="US">United States</option>
                  <option value="GB">United Kingdom</option>
                  <option value="CA">Canada</option>
                  <option value="EU">European Union</option>
                  <option value="OTHER">Other / international</option>
                </select>
              </Field>

              <label className="checkbox-label">
                <input
                  type="checkbox"
                  name="monitoring"
                  defaultChecked={data.workspace.settings.monitoring}
                />
                Refresh public threat context on scheduled runs
              </label>
              <p className="field-hint">
                Monitoring updates public context. It does not re-verify your
                account or device settings. Check your exposure page for
                changes.
              </p>
              <button
                type="submit"
                className="button primary"
                disabled={pending}
              >
                {pending ? "Saving…" : "Save preferences"}
              </button>
            </form>
          </details>
          <details
            id="integrations"
            className="settings-section"
            open={window.location.hash === "#integrations"}
          >
            <summary>Connected services</summary>
            <h2>Connected services</h2>
            <p>
              Bring your own provider keys. They are encrypted at rest and never
              returned to your browser.
            </p>
            <ErrorMessage error={integrationError} />
            {(["hibp", "brave"] as const).map((provider) => {
              const configured = integrations?.[provider]?.configured;
              return (
                <div className="provider-setting" key={provider}>
                  <div>
                    <h3>
                      {provider === "hibp"
                        ? "Have I Been Pwned"
                        : "Brave Search"}
                    </h3>
                    <span className="quiet-badge">
                      {configured ? "Connected" : "Not connected"}
                    </span>
                  </div>
                  <p>
                    {provider === "hibp"
                      ? "Check known breaches for your verified sign-in email. Your HIBP subscription must support account searches."
                      : "Search the public web for your own identifiers and review possible matches."}
                  </p>
                  {configured ? (
                    <button
                      type="button"
                      className="button secondary"
                      disabled={pending || demo}
                      onClick={() => disconnect(provider)}
                    >
                      Disconnect
                    </button>
                  ) : (
                    <form
                      className="provider-form"
                      onSubmit={(e) => integration(e, provider)}
                    >
                      <Field name={`${provider}-key`} label="Provider API key">
                        <input
                          id={`${provider}-key`}
                          name="apiKey"
                          type="password"
                          autoComplete="off"
                          required
                          maxLength={256}
                          disabled={demo}
                        />
                      </Field>
                      <button
                        type="submit"
                        className="button secondary"
                        disabled={pending || demo}
                      >
                        Connect {provider === "hibp" ? "HIBP" : "Brave"}
                      </button>
                    </form>
                  )}
                </div>
              );
            })}
            <div className="provider-setting">
              <div>
                <h3>Email ownership verification</h3>
                <span className="quiet-badge">
                  {session?.user.emailVerified
                    ? "Verified"
                    : integrations?.emailVerification.available
                      ? "Available"
                      : "Sender setup required"}
                </span>
              </div>
              <p>
                {session?.user.emailVerified
                  ? "Your sign-in email is verified and eligible for HIBP ownership checks."
                  : integrations?.emailVerification.available
                    ? "Verify your sign-in email before querying account breach information."
                    : "The deployment needs a configured email sender before email ownership checks can run. Other audit features remain available."}
              </p>
              {integrations?.emailVerification.available &&
                !session?.user.emailVerified && (
                  <button
                    type="button"
                    className="button secondary"
                    disabled={demo}
                    onClick={async () => {
                      const r = await authClient.sendVerificationEmail({
                        email: session?.user.email ?? "",
                        callbackURL: "/?panel=settings",
                      });
                      if (r.error) setError(new Error(r.error.message));
                      else notify("Verification email sent. Check your inbox.");
                    }}
                  >
                    Send verification email
                  </button>
                )}
            </div>
          </details>
          <details
            id="account"
            className="settings-section"
            open={window.location.hash === "#account"}
          >
            <summary>Account security</summary>
            <h2>Protect your Palisade account</h2>
            <p>
              Keep the security record itself protected with a passkey or an
              authenticator.
            </p>
            <div className="provider-setting">
              <h3>Passkeys</h3>
              {passkeys.map((key) => (
                <div className="subject-row" key={key.id}>
                  <span>{key.name || "Passkey"}</span>
                  <button
                    type="button"
                    className="button ghost"
                    onClick={async () => {
                      const r = await authClient.passkey.deletePasskey({
                        id: key.id,
                      });
                      if (r.error) setError(new Error(r.error.message));
                      else setPasskeys(passkeys.filter((k) => k.id !== key.id));
                    }}
                  >
                    Remove
                  </button>
                </div>
              ))}
              <button
                type="button"
                className="button secondary"
                disabled={demo}
                onClick={addPasskey}
              >
                <KeyIcon />
                Add a passkey
              </button>
            </div>
            <div className="provider-setting">
              <h3>Authenticator app</h3>
              <p>Use a six-digit TOTP code as an additional sign-in step.</p>
              {securityMessage && (
                <p className="inline-note" role="status">
                  {securityMessage}
                </p>
              )}
              {twoFactor ? (
                <>
                  <p>
                    Scan this code with your authenticator app, then verify the
                    first code.
                  </p>
                  {qr && (
                    <img
                      className="totp-qr"
                      src={qr}
                      width={192}
                      height={192}
                      alt="Authenticator setup QR code"
                    />
                  )}
                  <details>
                    <summary>Manual setup URI</summary>
                    <pre className="secret-output">{twoFactor.totpURI}</pre>
                  </details>
                  <form onSubmit={confirm2FA}>
                    <Field name="totp-code" label="Authenticator code">
                      <input
                        id="totp-code"
                        name="totp-code"
                        inputMode="numeric"
                        pattern="[0-9]{6}"
                        autoComplete="one-time-code"
                        required
                      />
                    </Field>
                    <button type="submit" className="button secondary">
                      Verify authenticator
                    </button>
                  </form>
                  <h4>Save your backup codes</h4>
                  <p>
                    These codes restore access if your authenticator is lost.
                    Keep them outside your audit notes.
                  </p>
                  <pre className="secret-output">
                    {twoFactor.backupCodes.join("\n")}
                  </pre>
                  <button
                    type="button"
                    className="button secondary"
                    onClick={() => {
                      setTwoFactor(null);
                      setQr("");
                    }}
                  >
                    I’ve saved my backup codes
                  </button>
                </>
              ) : (session?.user as any)?.twoFactorEnabled ? (
                <form onSubmit={disable2FA}>
                  <p className="inline-note">
                    Two-factor authentication is enabled.
                  </p>
                  <Field
                    name="disable-password"
                    label="Current password to disable"
                  >
                    <input
                      id="disable-password"
                      name="disable-password"
                      type="password"
                      autoComplete="current-password"
                      required
                      disabled={demo}
                    />
                  </Field>
                  <button
                    type="submit"
                    className="button secondary"
                    disabled={demo}
                  >
                    Disable two-factor authentication
                  </button>
                </form>
              ) : (
                <form onSubmit={setup2FA}>
                  <Field name="current-password" label="Current password">
                    <input
                      id="current-password"
                      name="current-password"
                      type="password"
                      autoComplete="current-password"
                      required
                      disabled={demo}
                    />
                  </Field>
                  <button
                    type="submit"
                    className="button secondary"
                    disabled={demo}
                  >
                    Set up authenticator
                  </button>
                </form>
              )}
            </div>
          </details>
          <details
            id="tokens"
            className="settings-section"
            open={window.location.hash === "#tokens"}
          >
            <summary>API & MCP access</summary>
            <div className="section-top">
              <div>
                <h2>API & MCP access</h2>
                <p>Give your CLI or agent only the access it needs.</p>
              </div>
              <button
                type="button"
                className="button secondary"
                disabled={demo}
                onClick={() => {
                  setCreatingToken(true);
                  setIssued("");
                }}
              >
                <PlusIcon />
                Create token
              </button>
            </div>
            <ErrorMessage error={tokenError} />
            {issued && (
              <div className="token-reveal">
                <h3>Copy your token now</h3>
                <p>
                  This is the only time it will be shown. Store it in your
                  agent’s secret settings.
                </p>
                <pre className="secret-output">{issued}</pre>
                <button
                  type="button"
                  className="button secondary"
                  onClick={async () => {
                    try {
                      await navigator.clipboard.writeText(issued);
                      notify("Token copied. Store it securely.");
                    } catch {
                      notify("Select and copy the token above.");
                    }
                  }}
                >
                  Copy token
                </button>
                <button
                  type="button"
                  className="button ghost"
                  onClick={() => setIssued("")}
                >
                  Dismiss
                </button>
              </div>
            )}
            {tokenData?.tokens.length ? (
              tokenData.tokens.map((token) => (
                <div className="token-row" key={token.id}>
                  <div>
                    <h3>{token.name}</h3>
                    <p>
                      <code>{token.prefix}…</code> · {token.scopes.join(", ")}
                    </p>
                    <p className="field-hint">
                      Expires {date(token.expiresAt)} · Last used{" "}
                      {token.lastUsedAt ? date(token.lastUsedAt) : "never"}
                    </p>
                  </div>
                  <button
                    type="button"
                    className="button ghost"
                    onClick={() => setRevoke(token)}
                  >
                    Revoke
                  </button>
                </div>
              ))
            ) : (
              <p className="muted">
                No active tokens. Create one when you’re ready to connect a
                tool.
              </p>
            )}
            <a
              href="https://github.com/jpamorgan/palisade/blob/main/docs/cli.md"
              target="_blank"
              rel="noreferrer"
              className="text-link"
            >
              CLI and MCP setup guide <ArrowRightIcon />
            </a>
          </details>
          <details
            id="data"
            className="settings-section"
            open={window.location.hash === "#data"}
          >
            <summary>Your data</summary>
            <h2>Your data, portable</h2>
            <p>
              Export your complete security record or merge a local CLI
              workspace. Imported observations earn no score credit until you
              verify them in this workspace.
            </p>
            <div className="row">
              <button
                type="button"
                className="button secondary"
                onClick={() => downloadWorkspace(data.workspace)}
              >
                <ArrowDownTrayIcon />
                Export workspace
              </button>
              <label className="button secondary file-button">
                <ArrowUpTrayIcon />
                Choose import file
                <input
                  type="file"
                  name="workspace-import"
                  accept=".json,application/json"
                  onChange={(e) => {
                    void prepareImport(e.target.files?.[0]);
                    e.target.value = "";
                  }}
                />
              </label>
            </div>
            {importFile && (
              <div className="verification-note">
                <h3>Ready to merge {importFile.name}</h3>
                <p>
                  Existing audit data will be retained. The server validates the
                  file before importing.
                </p>
                <div className="row">
                  <button
                    type="button"
                    className="button secondary"
                    disabled={pending}
                    onClick={importWorkspace}
                  >
                    Merge workspace
                  </button>
                  <button
                    type="button"
                    className="button ghost"
                    onClick={() => {
                      setImportFile(null);
                      setImportReady(null);
                    }}
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}
            <div className="delete-section">
              <h3>Delete private audit data</h3>
              <p>
                Remove your workspace, audit history, integrations, and API
                tokens. This cannot be undone. Your login account remains.
              </p>
              <button
                type="button"
                className="button secondary"
                disabled={demo}
                onClick={() => setDeleting(true)}
              >
                Delete audit data
              </button>
            </div>
          </details>
        </div>
      </div>
      {creatingToken && (
        <Modal
          title="Create an access token"
          onClose={() => setCreatingToken(false)}
        >
          <form className="modal-form" onSubmit={issue}>
            <Field name="token-name" label="Token name">
              <input
                id="token-name"
                name="token-name"
                required
                maxLength={100}
                placeholder="e.g. Codex on my Mac"
                autoFocus
              />
            </Field>
            <fieldset>
              <legend>Access scopes</legend>
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  name="scope"
                  value="read"
                  defaultChecked
                />
                Read audit results
              </label>
              <label className="checkbox-label">
                <input type="checkbox" name="scope" value="write" />
                Write evidence and manage audit state
              </label>
              <label className="checkbox-label">
                <input type="checkbox" name="scope" value="scan" />
                Run provider scans
              </label>
            </fieldset>
            <Field name="expiry" label="Expires after">
              <select id="expiry" name="expiry" defaultValue="30">
                <option value="7">7 days</option>
                <option value="30">30 days</option>
                <option value="90">90 days</option>
              </select>
            </Field>
            <ErrorMessage error={error} />
            <button type="submit" className="button primary" disabled={pending}>
              Create token <KeyIcon />
            </button>
          </form>
        </Modal>
      )}
      {revoke && (
        <Modal title={`Revoke ${revoke.name}?`} onClose={() => setRevoke(null)}>
          <div className="modal-form">
            <p>
              Tools using this token will immediately lose access. You can
              create a new token at any time.
            </p>
            <ErrorMessage error={error} />
            <button
              type="button"
              className="button primary danger"
              disabled={pending}
              onClick={async () => {
                try {
                  await mutate(`/tokens/${revoke.id}`, undefined, "DELETE");
                  setRevoke(null);
                  notify("Token revoked.");
                } catch (e) {
                  setError(e);
                }
              }}
            >
              Revoke token
            </button>
          </div>
        </Modal>
      )}
      {deleting && (
        <Modal
          title="Delete your private audit data?"
          onClose={() => setDeleting(false)}
        >
          <div className="modal-form">
            <p>
              This permanently deletes your current workspace, evidence,
              history, integrations, and access tokens. Export a copy first if
              you want to keep your record.
            </p>
            <Field name="delete-confirmation" label="Type DELETE to confirm">
              <input
                id="delete-confirmation"
                name="delete-confirmation"
                value={confirmation}
                onChange={(e) => setConfirmation(e.target.value)}
              />
            </Field>
            <ErrorMessage error={error} />
            <button
              type="button"
              className="button primary danger"
              disabled={confirmation !== "DELETE" || pending}
              onClick={async () => {
                try {
                  await mutate(
                    "/workspace",
                    { confirmation: "DELETE" },
                    "DELETE",
                  );
                  window.location.assign("/");
                } catch (e) {
                  setError(e);
                }
              }}
            >
              Delete audit data
            </button>
          </div>
        </Modal>
      )}
    </>
  );
}
