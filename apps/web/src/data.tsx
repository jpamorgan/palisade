import { createContext, useContext, useState, type ReactNode } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  CHECKS,
  createWorkspace,
  evaluateWorkspace,
  recordEvidence,
  createSnapshot,
  addAsset,
  updateAsset,
  removeAsset,
  recordAction,
  mergeWorkspace,
  type Workspace,
  type Evaluation,
} from "@palisade/core";

export interface Envelope {
  workspace: Workspace;
  evaluation: Evaluation;
  revision: number;
  receipt?: { status: string; message: string };
}
export class ApiError extends Error {
  constructor(
    public code: string,
    message: string,
  ) {
    super(message);
  }
}
export async function api<T>(
  path: string,
  body?: unknown,
  method?: string,
): Promise<T> {
  const res = await fetch(`/api/v1${path}`, {
    method: method ?? (body === undefined ? "GET" : "POST"),
    credentials: "same-origin",
    headers:
      body === undefined ? undefined : { "Content-Type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  let data: any;
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    throw new ApiError(
      "INVALID_RESPONSE",
      "The service returned an unexpected response. Please try again.",
    );
  }
  if (!res.ok)
    throw new ApiError(
      data.error?.code ?? String(res.status),
      data.error?.message ?? "This request could not be completed.",
    );
  return data as T;
}
function seedDemo(): Workspace {
  let w = createWorkspace("Your personal workspace");
  for (const a of [
    {
      kind: "email",
      label: "Primary email",
      value: "alex@example.com",
      critical: true,
    },
    { kind: "phone", label: "Personal phone", critical: true },
    { kind: "device", label: "Personal MacBook", critical: true },
    { kind: "financial", label: "Everyday banking", critical: true },
    { kind: "password_manager", label: "Password manager", critical: true },
    { kind: "network", label: "Home network", critical: false },
  ] as const)
    w = addAsset(w, a);
  CHECKS.forEach((check, i) => {
    if (i % 4 === 3 || !check.acceptedMethods.includes("guided")) return;
    const assets = check.assetKinds?.length
      ? w.assets.filter((a) => check.assetKinds!.includes(a.kind))
      : [undefined];
    for (const asset of assets)
      w = recordEvidence(w, {
        checkId: check.id,
        assetId: asset?.id,
        status:
          i % 7 === 1
            ? "fail"
            : i % 6 === 2 && check.partialCriteria
              ? "partial"
              : "pass",
        method: "guided",
        notes:
          "Illustrative demo evidence. This is not an assessment of your security.",
      });
  });
  return createSnapshot(w);
}
function loadDemo(): Workspace {
  try {
    const saved = sessionStorage.getItem("palisade-demo");
    if (saved) return JSON.parse(saved);
  } catch {}
  return seedDemo();
}
interface DataContextValue {
  data?: Envelope;
  userId: string;
  loading: boolean;
  error: Error | null;
  demo: boolean;
  pending: boolean;
  base: string;
  mutate: <T = Envelope>(
    path: string,
    body?: any,
    method?: string,
  ) => Promise<T>;
  refresh: () => void;
  notify: (message: string) => void;
}
const DataContext = createContext<DataContextValue | null>(null);
export const auditKeys = {
  workspace: (userId: string) => ["workspace", userId] as const,
  integrations: (userId: string) => ["integrations", userId] as const,
  tokens: (userId: string) => ["tokens", userId] as const,
  activity: (userId: string) => ["activity", userId] as const,
};
export function DataProvider({
  children,
  userId = "demo",
}: {
  children: ReactNode;
  userId?: string;
}) {
  const demo = userId === "demo";
  const [demoWorkspace, setDemoWorkspace] = useState<Workspace>(() =>
    loadDemo(),
  );
  const [pending, setPending] = useState(false);
  const [notice, setNotice] = useState("");
  const client = useQueryClient();
  const query = useQuery({
    queryKey: auditKeys.workspace(userId),
    queryFn: () => api<Envelope>("/workspace"),
    enabled: !demo,
    retry: 1,
    refetchOnWindowFocus: true,
  });
  const data = demo
    ? {
        workspace: demoWorkspace,
        evaluation: evaluateWorkspace(demoWorkspace),
        revision: 1,
      }
    : query.data;
  function notify(message: string) {
    setNotice(message);
  }
  async function mutate<T = Envelope>(
    path: string,
    body?: any,
    method?: string,
  ): Promise<T> {
    setPending(true);
    try {
      if (demo) {
        let next = demoWorkspace;
        if (path === "/evidence")
          next = recordEvidence(next, { ...body, method: "guided" });
        else if (path === "/assets" && method !== "DELETE")
          next = addAsset(next, body);
        else if (path.startsWith("/assets/") && method === "PATCH")
          next = updateAsset(next, path.split("/").pop()!, body);
        else if (path.startsWith("/assets/") && method === "DELETE")
          next = removeAsset(next, path.split("/").pop()!);
        else if (path === "/actions") next = recordAction(next, body);
        else if (path === "/audits") next = createSnapshot(next);
        else if (
          path.startsWith("/audits/") &&
          method === "DELETE" &&
          body?.confirmation === "DELETE"
        )
          next = {
            ...next,
            snapshots: next.snapshots.filter(
              (s) => s.id !== path.split("/").pop(),
            ),
          };
        else if (path === "/imports")
          next = mergeWorkspace(next, body.workspace);
        else if (path === "/workspace" && method === "PATCH")
          next = {
            ...next,
            ...(body.name ? { name: body.name } : {}),
            settings: { ...next.settings, ...body.settings },
          };
        else
          throw new Error(
            "Create a private workspace to use live integrations and API access. The demo runs only in this browser tab.",
          );
        setDemoWorkspace(next);
        sessionStorage.setItem("palisade-demo", JSON.stringify(next));
        return {
          workspace: next,
          evaluation: evaluateWorkspace(next),
          revision: 1,
        } as T;
      }
      const result = await api<T>(path, body, method);
      if (result && typeof result === "object" && "workspace" in result)
        client.setQueryData(auditKeys.workspace(userId), result);
      await Promise.all([
        client.invalidateQueries({ queryKey: auditKeys.integrations(userId) }),
        client.invalidateQueries({ queryKey: auditKeys.tokens(userId) }),
        client.invalidateQueries({ queryKey: auditKeys.activity(userId) }),
      ]);
      return result;
    } catch (error) {
      notify(
        error instanceof Error
          ? error.message
          : "The request could not be completed.",
      );
      throw error;
    } finally {
      setPending(false);
    }
  }
  return (
    <DataContext.Provider
      value={{
        data,
        userId,
        loading: !demo && query.isPending,
        error: demo ? null : query.error,
        demo,
        pending,
        base: demo ? "/?demo=1" : "/",
        mutate,
        refresh: () => {
          void query.refetch();
        },
        notify,
      }}
    >
      {children}
      {notice && (
        <div className="toast" role="status">
          <span>{notice}</span>
          <button
            type="button"
            aria-label="Dismiss notification"
            onClick={() => setNotice("")}
          >
            ×
          </button>
        </div>
      )}
    </DataContext.Provider>
  );
}
export function useAudit() {
  const value = useContext(DataContext);
  if (!value) throw new Error("Audit context is missing");
  return value;
}
export function downloadWorkspace(workspace: Workspace) {
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(workspace, null, 2)], {
      type: "application/json",
    }),
  );
  const a = document.createElement("a");
  a.href = url;
  a.download = `palisade-audit-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export function date(value?: string) {
  return value
    ? new Date(value).toLocaleDateString(undefined, {
        month: "short",
        day: "numeric",
        year: "numeric",
      })
    : "Not yet assessed";
}

export async function readWorkspaceImport(file: File): Promise<unknown> {
  if (file.size > 5_000_000)
    throw new Error("Choose a JSON file smaller than 5 MB.");
  const parsed = JSON.parse(await file.text());
  if (
    !parsed ||
    parsed.schemaVersion !== 1 ||
    !Array.isArray(parsed.assets) ||
    !Array.isArray(parsed.evidence)
  )
    throw new Error("This does not look like a Palisade workspace export.");
  if (new TextEncoder().encode(JSON.stringify(parsed)).byteLength > 1_000_000)
    throw new Error(
      "Workspace data exceeds the 1 MB limit. Export a backup and remove older snapshots before importing.",
    );
  return parsed;
}

export function auditHref(base: string, values: Record<string, string>) {
  const params = new URL(base, "https://palisade.invalid").searchParams;
  for (const [key, value] of Object.entries(values)) params.set(key, value);
  return `/?${params.toString()}`;
}
