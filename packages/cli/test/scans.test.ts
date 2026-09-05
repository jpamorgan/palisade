import { afterEach, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { LocalService, type LocalServiceOptions } from "../src/service";
import { renderReport } from "../src/report";
const directories: string[] = [];
async function fixture(options: LocalServiceOptions) {
  const dir = await mkdtemp(join(tmpdir(), "palisade-scans-"));
  directories.push(dir);
  const service = new LocalService(dir, options);
  await service.init("Test audit");
  return service;
}
afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((dir) => rm(dir, { recursive: true, force: true })),
  );
});
test("failed HIBP retry records unknown and retains historical exposure", async () => {
  let failing = false;
  const service = await fixture({
    env: { HIBP_API_KEY: "a".repeat(32) },
    fetch: (async () =>
      failing
        ? new Response(null, { status: 503 })
        : Response.json([
            {
              Name: "Example",
              Title: "Example breach",
              Domain: "example.test",
              BreachDate: "2026-01-01",
              AddedDate: "2026-01-02T00:00:00Z",
              DataClasses: ["Email addresses"],
              IsVerified: true,
            },
          ])) as unknown as typeof fetch,
  });
  const added: any = await service.request("POST", "/assets", {
    kind: "email",
    label: "Test email",
    value: "owner@example.test",
    critical: true,
  });
  const assetId = added.workspace.assets[0].id;
  const success: any = await service.request("POST", "/scans/hibp", {
    assetId,
    consent: true,
  });
  expect(
    success.evaluation.checks.find(
      (c: any) => c.checkId === "exposure.breach-review",
    ).status,
  ).toBe("pass");
  failing = true;
  await new Promise((resolve) => setTimeout(resolve, 5));
  const failed: any = await service.request("POST", "/scans/hibp", {
    assetId,
    consent: true,
  });
  expect(failed.receipt.status).not.toBe("ok");
  expect(failed.workspace.evidence.at(-1).status).toBe("unknown");
  expect(
    failed.evaluation.checks.find(
      (c: any) => c.checkId === "exposure.breach-review",
    ).earnedPoints,
  ).toBe(0);
  expect(failed.workspace.threatEvents).toHaveLength(1);
});
test("partial public feed outage persists available reports without improving score", async () => {
  const service = await fixture({
    fetch: (async (url: string | URL | Request) =>
      String(url).includes("cisa.gov")
        ? Response.json({
            vulnerabilities: [
              {
                cveID: "CVE-2026-9999",
                vendorProject: "Test",
                product: "Test",
                vulnerabilityName: "Test report",
                dateAdded: "2026-01-01",
                shortDescription: "Test vulnerability",
                requiredAction: "Update",
              },
            ],
          })
        : new Response(null, { status: 503 })) as unknown as typeof fetch,
  });
  const result: any = await service.request("POST", "/scans/threats", {});
  expect(result.receipt.status).toBe("unavailable");
  expect(result.workspace.threatEvents).toHaveLength(1);
  expect(result.workspace.threatEvents[0].relevance).toBe("unassessed");
  expect(result.evaluation.score).toBeNull();
});
test("Mac enabled firewall remains unknown pending exception review while FileVault can pass", async () => {
  const service = await fixture({
    macCollector: async () => ({
      status: "complete",
      message: "Test settings",
      observations: [
        {
          collector: "filevault",
          status: "pass",
          summary: "FileVault disk encryption is enabled.",
          facts: { enabled: true },
        },
        {
          collector: "firewall",
          status: "pass",
          summary: "Application firewall is enabled.",
          facts: { enabled: true },
        },
      ],
    }),
  });
  const added: any = await service.request("POST", "/assets", {
    kind: "device",
    label: "Test laptop",
    critical: true,
  });
  const assetId = added.workspace.assets[0].id;
  const result: any = await service.request("POST", "/scans/mac", {
    assetId,
    consent: true,
  });
  expect(
    result.evaluation.checks.find(
      (c: any) => c.checkId === "devices.disk-encryption",
    ).status,
  ).toBe("pass");
  expect(
    result.evaluation.checks.find((c: any) => c.checkId === "devices.firewall")
      .status,
  ).toBe("unknown");
  const report = renderReport(result.workspace, result.evaluation);
  expect(report).toContain("Test laptop");
  expect(report).toContain("Review permitted inbound applications");
});
test("public-name identity search uses label and keeps result unconfirmed", async () => {
  let query = "";
  const service = await fixture({
    env: { BRAVE_SEARCH_API_KEY: "test-key" },
    fetch: (async (url: string | URL | Request) => {
      query = new URL(String(url)).searchParams.get("q") ?? "";
      return Response.json({
        query: { original: query },
        web: {
          results: [
            {
              title: "Test profile",
              url: "https://example.test/profile",
              description: "Synthetic result",
            },
          ],
        },
      });
    }) as unknown as typeof fetch,
  });
  const added: any = await service.request("POST", "/assets", {
    kind: "identity",
    label: "Example Test Person",
    critical: false,
  });
  const result: any = await service.request("POST", "/scans/footprint", {
    assetId: added.workspace.assets[0].id,
    consent: true,
  });
  expect(query).toBe("Example Test Person");
  expect(result.workspace.threatEvents[0].relevance).toBe("unassessed");
  expect(result.evaluation.score).toBeNull();
});
test("local collector cannot attach in-flight evidence after the selected device identifier changes", async () => {
  let finish:
    | ((
        value: Awaited<
          ReturnType<NonNullable<LocalServiceOptions["macCollector"]>>
        >,
      ) => void)
    | undefined;
  let started: (() => void) | undefined;
  const signal = new Promise<void>((resolve) => {
    started = resolve;
  });
  const service = await fixture({
    macCollector: () => {
      started!();
      return new Promise((resolve) => {
        finish = resolve;
      });
    },
  });
  const added: any = await service.request("POST", "/assets", {
    kind: "device",
    label: "Test laptop",
    value: "Device A",
    critical: true,
  });
  const assetId = added.workspace.assets[0].id;
  const scanning = service.request("POST", "/scans/mac", {
    assetId,
    consent: true,
  });
  await signal;
  await service.request("PATCH", "/assets/" + assetId, { value: "Device B" });
  finish!({
    status: "complete",
    message: "Test",
    observations: [
      {
        collector: "filevault",
        status: "pass",
        summary: "Encryption enabled.",
        facts: { enabled: true },
      },
    ],
  });
  await expect(scanning).rejects.toMatchObject({ code: "ASSET_CHANGED" });
  const current: any = await service.request("GET", "/workspace");
  expect(current.workspace.evidence).toHaveLength(0);
});
test("local preference revisions reject stale concurrent edits and change on metadata updates", async () => {
  const service = await fixture({});
  const before: any = await service.request("GET", "/workspace");
  const first: any = await service.request("PATCH", "/workspace", {
    revision: before.revision,
    name: "First client name",
  });
  expect(Number.isSafeInteger(first.revision)).toBe(true);
  expect(first.revision).not.toBe(before.revision);
  await expect(
    service.request("PATCH", "/workspace", {
      revision: before.revision,
      name: "Stale client name",
      settings: { region: "CA" },
    }),
  ).rejects.toMatchObject({ code: "REVISION_CONFLICT" });
  const read: any = await service.request("GET", "/workspace");
  expect(read.workspace.name).toBe("First client name");
  expect(read.workspace.settings.region).toBe("unspecified");
  expect(read.revision).toBe(first.revision);
  const next: any = await service.request("PATCH", "/workspace", {
    revision: read.revision,
    settings: { region: "CA" },
  });
  expect(next.workspace.settings.region).toBe("CA");
  expect(next.revision).not.toBe(first.revision);
});
