import { describe, expect, test } from "bun:test";
import { renderToString } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  createWorkspace,
  evaluateWorkspace,
  createSnapshot,
} from "@palisade/core";
import { DataProvider, auditKeys, useAudit, readWorkspaceImport } from "./data";

function ReadWorkspace() {
  const { data, loading } = useAudit();
  return (
    <p>
      {data?.workspace.name ??
        (loading ? "Loading current account" : "No workspace")}
    </p>
  );
}

describe("private web query isolation", () => {
  test("a different signed-in account cannot render the previous account cached workspace", () => {
    const client = new QueryClient({
      defaultOptions: { queries: { staleTime: 60_000 } },
    });
    const alice = createWorkspace("Alice private security record");
    client.setQueryData(auditKeys.workspace("alice"), {
      workspace: alice,
      evaluation: evaluateWorkspace(alice),
      revision: 1,
    });
    const render = (userId: string) =>
      renderToString(
        <QueryClientProvider client={client}>
          <MemoryRouter initialEntries={["/"]}>
            <DataProvider key={userId} userId={userId}>
              <ReadWorkspace />
            </DataProvider>
          </MemoryRouter>
        </QueryClientProvider>,
      );
    expect(render("alice")).toContain("Alice private security record");
    const bob = render("bob");
    expect(bob).not.toContain("Alice private security record");
    expect(bob).toContain("Loading current account");
    client.clear();
  });
  test("integration and token metadata caches are scoped to the same account identity", () => {
    const client = new QueryClient();
    client.setQueryData(auditKeys.integrations("alice"), {
      hibp: { configured: true },
    });
    client.setQueryData(auditKeys.tokens("alice"), {
      tokens: [{ name: "Alice agent" }],
    });
    client.setQueryData(auditKeys.activity("alice"), {
      items: [{ summary: "Alice activity" }],
    });
    expect(client.getQueryData(auditKeys.integrations("bob"))).toBeUndefined();
    expect(client.getQueryData(auditKeys.tokens("bob"))).toBeUndefined();
    expect(client.getQueryData(auditKeys.activity("bob"))).toBeUndefined();
    client.clear();
  });
});

describe("workspace export portability", () => {
  test("pretty-printed valid exports are measured by compact data size", async () => {
    let workspace = createWorkspace("Portable synthetic audit");
    for (let i = 0; i < 25; i++) workspace = createSnapshot(workspace);
    const formatted = JSON.stringify(workspace, null, 2);
    expect(new TextEncoder().encode(formatted).byteLength).toBeGreaterThan(
      1_000_000,
    );
    expect(
      new TextEncoder().encode(JSON.stringify(workspace)).byteLength,
    ).toBeLessThan(1_000_000);
    const imported = await readWorkspaceImport(
      new File([formatted], "audit.json", { type: "application/json" }),
    );
    expect(imported).toEqual(workspace);
  });
  test("oversized audit data and malformed exports get actionable errors", async () => {
    const workspace = {
      ...createWorkspace("Size fixture"),
      name: "x".repeat(1_000_001),
    };
    await expect(
      readWorkspaceImport(new File([JSON.stringify(workspace)], "large.json")),
    ).rejects.toThrow("1 MB");
    await expect(
      readWorkspaceImport(new File(['{"schemaVersion":1}'], "bad.json")),
    ).rejects.toThrow("workspace export");
  });
});
