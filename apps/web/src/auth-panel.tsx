import { useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { ArrowRightIcon } from "@heroicons/react/16/solid";
import { authClient } from "./auth";
import { Brand, ErrorMessage, Field } from "./ui";

export function AuthPanel({ signup = false }: { signup?: boolean }) {
  const navigate = useNavigate();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [challenge, setChallenge] = useState(false);
  const [backup, setBackup] = useState(false);
  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const f = new FormData(e.currentTarget);
    try {
      const result = signup
        ? await authClient.signUp.email({
            name: String(f.get("name")),
            email: String(f.get("email")),
            password: String(f.get("password")),
          })
        : await authClient.signIn.email({
            email: String(f.get("email")),
            password: String(f.get("password")),
          });
      if (result.error) throw new Error(result.error.message);
      if ((result.data as any)?.twoFactorRedirect) {
        setChallenge(true);
        return;
      }
      navigate("/");
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }
  async function verify(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const code = String(new FormData(e.currentTarget).get("code"));
      const result = backup
        ? await authClient.twoFactor.verifyBackupCode({ code })
        : await authClient.twoFactor.verifyTotp({ code });
      if (result.error) throw new Error(result.error.message);
      navigate("/");
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }
  async function passkey() {
    setBusy(true);
    setError(null);
    try {
      const result = await authClient.signIn.passkey();
      if (result.error) throw new Error(result.error.message);
      navigate("/");
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="auth-panel">
      <p>
        {challenge
          ? backup
            ? "Enter an unused backup code."
            : "Enter the six-digit code from your authenticator."
          : signup
            ? "Save your checklist in a private workspace."
            : "Sign in to continue your private audit."}
      </p>
      <form onSubmit={challenge ? verify : submit}>
        {challenge ? (
          <Field
            label={backup ? "Backup code" : "Authenticator code"}
            name="code"
          >
            <input
              key={backup ? "backup" : "totp"}
              id="code"
              name="code"
              autoComplete="one-time-code"
              inputMode={backup ? "text" : "numeric"}
              pattern={backup ? undefined : "[0-9]{6}"}
              autoFocus
              required
            />
          </Field>
        ) : (
          <>
            {signup && (
              <Field name="name" label="Your name">
                <input
                  id="name"
                  name="name"
                  autoComplete="name"
                  required
                  maxLength={100}
                  autoFocus
                />
              </Field>
            )}
            <Field name="email" label="Email address">
              <input
                id="email"
                name="email"
                type="email"
                autoComplete="email"
                required
                autoFocus={!signup}
              />
            </Field>
            <Field
              name="password"
              label="Password"
              hint={
                signup
                  ? "At least 12 characters. You can add a passkey later."
                  : undefined
              }
            >
              <input
                id="password"
                name="password"
                type="password"
                minLength={signup ? 12 : 1}
                maxLength={128}
                autoComplete={signup ? "new-password" : "current-password"}
                required
              />
            </Field>
          </>
        )}
        <ErrorMessage error={error} />
        <button type="submit" className="button primary" disabled={busy}>
          {busy
            ? "Please wait…"
            : challenge
              ? "Verify and continue"
              : signup
                ? "Create workspace"
                : "Sign in"}
          <ArrowRightIcon />
        </button>
      </form>
      {challenge && (
        <button
          type="button"
          className="button secondary"
          onClick={() => {
            setBackup(!backup);
            setError(null);
          }}
        >
          {backup ? "Use my authenticator" : "Use a backup code"}
        </button>
      )}
      {!signup && !challenge && (
        <>
          <button
            type="button"
            className="button secondary"
            disabled={busy}
            onClick={passkey}
          >
            Sign in with a passkey
          </button>
          <Link to="/reset-password" className="forgot-link">
            Forgot your password?
          </Link>
        </>
      )}
      <p className="auth-switch">
        {signup ? "Already have an account?" : "New to Palisade?"}{" "}
        <Link to={signup ? "/?auth=signin" : "/?auth=signup"}>
          {signup ? "Sign in" : "Create a workspace"}
        </Link>
      </p>
      <details className="auth-privacy">
        <summary>How your data is handled</summary>
        <p>
          Your private audit is stored encrypted on Cloudflare. Provider scans
          disclose only the identifiers you explicitly select and consent to.
          Keep passwords, recovery codes, and identity-document numbers out of
          audit notes.
        </p>
      </details>
    </div>
  );
}
export function ResetPassword() {
  const [params] = useSearchParams();
  const token = params.get("token");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [done, setDone] = useState(false);
  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const f = new FormData(e.currentTarget);
    try {
      const result = token
        ? await authClient.resetPassword({
            newPassword: String(f.get("new-password")),
            token,
          })
        : await authClient.requestPasswordReset({
            email: String(f.get("email")),
            redirectTo: `${window.location.origin}/reset-password`,
          });
      if (result.error) throw new Error(result.error.message);
      setDone(true);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="recovery-page">
      <header>
        <Brand />
        <Link to="/?auth=signin">Back to sign in</Link>
      </header>
      <main>
        <h1>{token ? "Choose a new password" : "Reset your password"}</h1>
        {done ? (
          <>
            <p role="status">
              {token
                ? "Your password has been reset. You can now sign in."
                : "If an account exists and email delivery is configured, a recovery link is on its way. Check your inbox."}
            </p>
            <Link className="button primary" to="/?auth=signin">
              Return to sign in
            </Link>
          </>
        ) : (
          <>
            <p>
              {token
                ? "Choose a unique password with at least 12 characters."
                : "Enter your sign-in email to request a recovery link."}
            </p>
            <form onSubmit={submit}>
              {token ? (
                <Field name="new-password" label="New password">
                  <input
                    id="new-password"
                    name="new-password"
                    type="password"
                    minLength={12}
                    maxLength={128}
                    autoComplete="new-password"
                    required
                  />
                </Field>
              ) : (
                <Field name="reset-email" label="Email address">
                  <input
                    id="reset-email"
                    name="email"
                    type="email"
                    autoComplete="email"
                    required
                  />
                </Field>
              )}
              <ErrorMessage error={error} />
              <button type="submit" className="button primary" disabled={busy}>
                {busy
                  ? "Please wait…"
                  : token
                    ? "Reset password"
                    : "Send recovery link"}
              </button>
            </form>
          </>
        )}
      </main>
    </div>
  );
}
