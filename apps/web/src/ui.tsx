import {
  useEffect,
  useRef,
  useId,
  type ReactNode,
  type CSSProperties,
} from "react";
import { Link } from "react-router-dom";
import { createPortal } from "react-dom";
import {
  XMarkIcon,
  CheckIcon,
  MinusIcon,
  ExclamationTriangleIcon,
  ClockIcon,
  QuestionMarkCircleIcon,
} from "@heroicons/react/16/solid";
import type { CheckStatus } from "@palisade/core";
export function Brand() {
  return (
    <Link to="/" className="brand" aria-label="Palisade homepage">
      palisade<span className="brand-period">.</span>
    </Link>
  );
}
export function Status({ status }: { status: CheckStatus }) {
  const labels: Record<CheckStatus, string> = {
    pass: "Verified",
    partial: "Partial",
    fail: "Needs attention",
    unknown: "Not checked",
    not_applicable: "Not applicable",
    stale: "Recheck due",
    conflict: "Conflicting evidence",
    imported: "Verify import",
  };
  const Icon =
    status === "pass"
      ? CheckIcon
      : status === "fail"
        ? ExclamationTriangleIcon
        : status === "stale"
          ? ClockIcon
          : status === "not_applicable"
            ? MinusIcon
            : QuestionMarkCircleIcon;
  return (
    <span className={`status status-${status}`}>
      <Icon />
      {labels[status]}
    </span>
  );
}
export function ScoreRing({
  score,
  coverage = 0,
  small = false,
}: {
  score: number | null;
  coverage?: number;
  small?: boolean;
}) {
  return (
    <div
      className={`score-ring ${small ? "small" : ""}`}
      style={
        {
          "--score": `${Math.min(100, Math.max(0, score ?? 0))}%`,
          "--coverage": `${coverage}%`,
        } as CSSProperties
      }
      role="img"
      aria-label={`Security posture ${score === null ? "not scored" : `${score} out of 100`}; ${coverage}% assessed`}
    >
      <div className="score-inner">
        <div className="score-value">
          {score === null ? "—" : score}
          <span>/100</span>
        </div>
        <p>{score === null ? "Start your audit" : "Security posture"}</p>
      </div>
    </div>
  );
}
export function PageHeading({
  eyebrow,
  title,
  description,
  action,
}: {
  eyebrow?: string;
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <header className="page-heading">
      <div>
        {eyebrow && <p className="eyebrow">{eyebrow}</p>}
        <h1>{title}</h1>
        <p className="page-description">{description}</p>
      </div>
      {action && <div className="heading-action">{action}</div>}
    </header>
  );
}
export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <div className="empty-line" />
      <h3>{title}</h3>
      <p>{description}</p>
      {action}
    </div>
  );
}
export function ErrorMessage({ error }: { error: unknown }) {
  return error ? (
    <p className="error-message" role="alert">
      {error instanceof Error ? error.message : String(error)}
    </p>
  ) : null;
}
export function Loading() {
  return (
    <div className="loading" role="status">
      <div className="spinner" />
      <p>Opening your workspace…</p>
    </div>
  );
}
export function Modal({
  title,
  children,
  onClose,
  wide = false,
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
  wide?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  useEffect(() => {
    const dialog = ref.current;
    const previous = document.querySelector<HTMLDialogElement>("dialog[open]");
    const previousFocus = document.activeElement as HTMLElement | null;
    if (previous && previous !== dialog) previous.close();
    dialog?.showModal();
    dialog?.querySelector<HTMLElement>("[autofocus]")?.focus();
    return () => {
      dialog?.close();
      if (previous?.isConnected) {
        previous.showModal();
        previousFocus?.focus();
      }
    };
  }, []);
  return createPortal(
    <dialog
      ref={ref}
      aria-labelledby={titleId}
      className={`modal ${wide ? "wide" : ""}`}
      onCancel={(e) => {
        e.preventDefault();
        e.stopPropagation();
        onClose();
      }}
      onClick={(e) => {
        e.stopPropagation();
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="modal-header">
        <h2 id={titleId}>{title}</h2>
        <button
          type="button"
          className="icon-button"
          aria-label="Close dialog"
          onClick={onClose}
        >
          <XMarkIcon />
        </button>
      </div>
      {children}
    </dialog>,
    document.body,
  );
}
export function Field({
  label,
  name,
  children,
  hint,
}: {
  label: string;
  name: string;
  children: ReactNode;
  hint?: string;
}) {
  return (
    <div className="field">
      <label htmlFor={name}>{label}</label>
      {children}
      {hint && <p className="field-hint">{hint}</p>}
    </div>
  );
}
export function Meter({ value }: { value: number }) {
  return (
    <div className="meter" aria-label={`${value}%`}>
      <div
        style={
          {
            "--progress": `${Math.min(100, Math.max(0, value))}%`,
          } as CSSProperties
        }
      />
    </div>
  );
}
