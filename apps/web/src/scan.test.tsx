import { afterEach, describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  createWorkspace,
  evaluateWorkspace,
  recordEvidence,
  recordAction,
  addAsset,
  CHECKS,
} from "@palisade/core";
import { z } from "zod";
import { AppRoutes, Landing, ScanResults } from "./app";
import {
  BootstrapSchema,
  ScanError,
  ScanStateSchema,
  copyText,
  forgetScan,
  loadScan,
  privateScanPath,
  readCapability,
  safeSourceUrl,
  saveScan,
  scanRequest,
  refreshAgent,
  type BootstrapScan,
  type ScanState,
} from "./scan-client";

const originalFetch = globalThis.fetch;
const originalNavigator = Object.getOwnPropertyDescriptor(
  globalThis,
  "navigator",
);
const originalStorage = Object.getOwnPropertyDescriptor(
  globalThis,
  "localStorage",
);
afterEach(() => {
  globalThis.fetch = originalFetch;
  if (originalNavigator)
    Object.defineProperty(globalThis, "navigator", originalNavigator);
  else Reflect.deleteProperty(globalThis, "navigator");
  if (originalStorage)
    Object.defineProperty(globalThis, "localStorage", originalStorage);
  else Reflect.deleteProperty(globalThis, "localStorage");
});
function fixture(): ScanState {
  const workspace = createWorkspace("Synthetic private scan");
  return {
    scan: {
      id: workspace.id,
      status: "waiting",
      phase: "Ready",
      message: "",
      run: 0,
      createdAt: workspace.createdAt,
      updatedAt: workspace.updatedAt,
      expiresAt: "2027-01-01T00:00:00Z",
    },
    workspace,
    evaluation: evaluateWorkspace(workspace),
    revision: 1,
    activity: [],
    target: { score: 85, coverage: 90, criticalGaps: 0, met: false },
  };
}
function bootstrap(): BootstrapScan {
  const id = crypto.randomUUID();
  return {
    id,
    readToken: "reader_" + "r".repeat(40),
    agentToken: "agent_" + "a".repeat(40),
    ownerToken: "owner_" + "o".repeat(40),
    viewUrl: `https://example.com/scan/${id}#key=reader_${"r".repeat(40)}`,
    mcpUrl: `https://example.com/mcp/scans/${id}`,
    expiresAt: "2027-01-01T00:00:00Z",
    agentExpiresAt: "2026-09-30T00:00:00Z",
  };
}

describe("the two-screen agent flow", () => {
  test("the landing page has exactly one action and explains the handoff", () => {
    const html = renderToStaticMarkup(
      <MemoryRouter>
        <Landing />
      </MemoryRouter>,
    );
    expect(html.match(/<button /g)?.length).toBe(1);
    expect(html).toContain("Copy agent prompt");
    expect(html).toContain("Paste into Codex, Claude, or your agent.");
    expect(html).not.toContain("<input");
    expect(html).not.toContain("Sign in");
    expect(html).not.toContain("Dashboard");
  });
  test("initial results never fabricate a score or verified checks", () => {
    const state = fixture();
    const html = renderToStaticMarkup(<ScanResults state={state} />);
    expect(html).toContain('aria-label="Not scored yet"');
    expect(html).toContain("0% assessed");
    expect(html).toContain("0 of 38 checks");
    expect(html.match(/class="category"/g)?.length).toBe(8);
    expect(html).not.toContain('class="check-status pass"');
  });
  test("new evidence changes the visible score and result while completed actions alone do not", () => {
    const initial = fixture();
    let workspace = addAsset(initial.workspace, {
      kind: "device",
      label: "Synthetic Mac",
      critical: true,
    });
    const assetId = workspace.assets[0]!.id;
    workspace = recordAction(workspace, {
      checkId: "devices.disk-encryption",
      assetId,
      status: "completed",
      notes: "Synthetic action, not yet verified.",
    });
    const actionOnly = {
      ...initial,
      workspace,
      evaluation: evaluateWorkspace(workspace),
    };
    expect(renderToStaticMarkup(<ScanResults state={actionOnly} />)).toContain(
      'aria-label="Not scored yet"',
    );
    workspace = recordEvidence(workspace, {
      checkId: "devices.disk-encryption",
      assetId,
      status: "pass",
      method: "guided",
      notes: "Synthetic FileVault observation confirmed by the user.",
      facts: {
        source_label: "User confirmation",
        source_url:
          "https://support.apple.com/guide/mac-help/protect-data-on-your-mac-with-filevault-mh11785/mac",
      },
    });
    const updated = {
      ...initial,
      workspace,
      evaluation: evaluateWorkspace(workspace),
      revision: 2,
    };
    const html = renderToStaticMarkup(<ScanResults state={updated} />);
    expect(html).not.toContain('aria-label="Not scored yet"');
    expect(html).toContain('class="check-status pass"');
    expect(html).toContain(
      "Synthetic FileVault observation confirmed by the user.",
    );
    expect(html).toContain("User confirmation");
    expect(html).toContain("View source");
    expect(html).toContain("1 of 38 checks");
  });
  test("a scan URL cannot render another scan's cached private results", () => {
    const client = new QueryClient();
    const alice = fixture();
    alice.workspace.name = "Alice private details";
    alice.scan.message = "Alice private status";
    const aliceToken = "a".repeat(43);
    client.setQueryData(["scan", alice.scan.id, aliceToken], alice);
    const render = (id: string, token: string) =>
      renderToStaticMarkup(
        <QueryClientProvider client={client}>
          <MemoryRouter initialEntries={[`/scan/${id}#key=${token}`]}>
            <AppRoutes />
          </MemoryRouter>
        </QueryClientProvider>,
      );
    expect(render(alice.scan.id, aliceToken)).toContain("Your security audit.");
    const bob = render(crypto.randomUUID(), "b".repeat(43));
    expect(bob).toContain("Opening your scan");
    expect(bob).not.toContain("Alice private status");
    client.clear();
  });
  test("not-applicable controls are excluded from progress and an excluded area is labeled honestly", () => {
    const state = fixture();
    for (const check of CHECKS.filter(
      (check) => check.categoryId === "network",
    )) {
      state.workspace = recordEvidence(state.workspace, {
        checkId: check.id,
        status: "not_applicable",
        method: "guided",
        notes: "Synthetic subject has no owned or managed home network.",
      });
    }
    state.evaluation = evaluateWorkspace(state.workspace);
    const html = renderToStaticMarkup(<ScanResults state={state} />);
    expect(html).toContain("0 of 34 checks");
    expect(html).toContain(
      'Home network</span><span class="category-meta">Not applicable',
    );
    expect(html).not.toContain("0/0");
  });
  test("critical recovery dependencies remain visible even when no control is failed", () => {
    const state = fixture();
    state.evaluation.findings.push({
      id: "synthetic-cycle",
      checkId: "recovery.channels",
      severity: "critical",
      title: "Review recovery dependencies",
      description: "Synthetic recovery accounts depend on each other.",
      kind: "dependency",
      action: "Verify an independent recovery method.",
    });
    state.target = { score: 85, coverage: 90, criticalGaps: 1, met: false };
    const html = renderToStaticMarkup(<ScanResults state={state} />);
    expect(html).toContain("1 critical gap");
    expect(html).toContain(
      'class="category-meta">Review recovery dependencies',
    );
    expect(html).toContain("Synthetic recovery accounts depend on each other.");
  });
});

describe("private handoff resilience", () => {
  test("an unexpired cached agent token is repaired after rotation elsewhere", async () => {
    const scan = {
      ...bootstrap(),
      agentExpiresAt: new Date(Date.now() + 86_400_000).toISOString(),
    };
    const freshToken = "pal_" + "n".repeat(43);
    const paths: string[] = [];
    globalThis.fetch = (async (
      input: RequestInfo | URL,
      init?: RequestInit,
    ) => {
      paths.push(String(input));
      if (init?.method === "GET") {
        expect(init.headers).toEqual({
          Authorization: `Bearer ${scan.agentToken}`,
        });
        return Response.json({ error: "revoked" }, { status: 401 });
      }
      expect(init?.method).toBe("POST");
      expect(init?.headers).toEqual({
        Authorization: `Bearer ${scan.ownerToken}`,
        "Content-Type": "application/json",
      });
      return Response.json({
        agentToken: freshToken,
        agentExpiresAt: new Date(Date.now() + 7 * 86_400_000).toISOString(),
      });
    }) as unknown as typeof fetch;
    const repaired = await refreshAgent(scan);
    expect(paths).toEqual([
      `/api/scans/${scan.id}`,
      `/api/scans/${scan.id}/agent-token`,
    ]);
    expect(repaired.agentToken).toBe(freshToken);
    expect(loadScan(scan.id)?.agentToken).toBe(freshToken);
    forgetScan(scan.id);
  });
  test("copying a working prompt keeps its credential and connection intact", async () => {
    const scan = {
      ...bootstrap(),
      agentExpiresAt: new Date(Date.now() + 86_400_000).toISOString(),
    };
    let calls = 0;
    globalThis.fetch = (async (
      _input: RequestInfo | URL,
      init?: RequestInit,
    ) => {
      calls++;
      expect(init?.method).toBe("GET");
      return Response.json(fixture());
    }) as unknown as typeof fetch;
    expect(await refreshAgent(scan)).toEqual(scan);
    expect(calls).toBe(1);
  });
  test("read capabilities stay in fragments and unsafe source schemes are never links", () => {
    const scan = bootstrap();
    const path = privateScanPath(scan);
    expect(path).toBe(`/scan/${scan.id}#key=${scan.readToken}`);
    expect(path).not.toContain(scan.ownerToken);
    expect(path).not.toContain(scan.agentToken);
    expect(readCapability(path.slice(path.indexOf("#")))).toBe(scan.readToken);
    expect(readCapability("#key=bad value")).toBeUndefined();
    expect(readCapability("#key=short")).toBeUndefined();
    expect(safeSourceUrl("javascript:alert(1)")).toBeUndefined();
    expect(safeSourceUrl("https://name:secret@example.com")).toBeUndefined();
    expect(safeSourceUrl("https://example.com/source")).toBe(
      "https://example.com/source",
    );
  });
  test("denied browser storage retains the active scan in this tab and deletion clears it", () => {
    Object.defineProperty(globalThis, "localStorage", {
      configurable: true,
      value: {
        setItem() {
          throw new Error("denied");
        },
        getItem() {
          throw new Error("denied");
        },
        removeItem() {
          throw new Error("denied");
        },
      },
    });
    const scan = bootstrap();
    expect(saveScan(scan)).toBe(false);
    expect(loadScan(scan.id)).toEqual(scan);
    forgetScan(scan.id);
    expect(loadScan(scan.id)).toBeUndefined();
  });
  test("clipboard rejection requests the selectable prompt fallback without claiming success", async () => {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: {
        clipboard: {
          writeText: async () => {
            throw new Error("NotAllowedError");
          },
        },
      },
    });
    expect(await copyText("private prompt")).toBe(false);
    let copied = "";
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: {
        clipboard: {
          writeText: async (value: string) => {
            copied = value;
          },
        },
      },
    });
    expect(await copyText("private prompt")).toBe(true);
    expect(copied).toBe("private prompt");
  });
  test("private reads use explicit bearer authorization without cookies or redirect forwarding", async () => {
    let called = false;
    globalThis.fetch = (async (
      input: RequestInfo | URL,
      init?: RequestInit,
    ) => {
      called = true;
      expect(input).toBe("/api/scans/test");
      expect(init?.headers).toEqual({ Authorization: "Bearer reader-secret" });
      expect(init?.credentials).toBe("omit");
      expect(init?.cache).toBe("no-store");
      expect(init?.redirect).toBe("error");
      expect(init?.signal).toBeDefined();
      return Response.json({ ok: true });
    }) as unknown as typeof fetch;
    expect(
      await scanRequest("/api/scans/test", {
        token: "reader-secret",
        schema: z.object({ ok: z.boolean() }),
      }),
    ).toEqual({ ok: true });
    expect(called).toBe(true);
  });
  test("revoked and malformed responses fail closed with useful messages", async () => {
    globalThis.fetch = (async () =>
      Response.json(
        { error: "denied" },
        { status: 401 },
      )) as unknown as typeof fetch;
    try {
      await scanRequest("/api/scans/test", { schema: z.unknown() });
      throw new Error("Unexpected success");
    } catch (error) {
      expect(error).toBeInstanceOf(ScanError);
      expect((error as ScanError).terminal).toBe(true);
    }
    globalThis.fetch = (async () =>
      Response.json({ score: 100 })) as unknown as typeof fetch;
    await expect(
      scanRequest("/api/scans/test", { schema: ScanStateSchema }),
    ).rejects.toThrow("unexpected response");
    expect(
      BootstrapSchema.safeParse({ ...bootstrap(), ownerToken: "short" })
        .success,
    ).toBe(false);
  });
});
