import { afterEach, expect, test } from "bun:test";
import { mkdtemp, rm, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { runCli } from "../src/cli";
import type { Workspace } from "@palisade/core";
const directories: string[] = [];
async function fixture() {
  const dir = await mkdtemp(join(tmpdir(), "palisade-cli-"));
  directories.push(dir);
  return {
    dir,
    async run(...args: string[]) {
      const out: string[] = [],
        err: string[] = [];
      const code = await runCli([...args, "--data-dir", dir, "--json"], {
        stdout: (text) => out.push(text),
        stderr: (text) => err.push(text),
      });
      return {
        code,
        out,
        err,
        data: out[0]?.startsWith("{") ? JSON.parse(out[0]) : null,
      };
    },
  };
}
afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((dir) => rm(dir, { recursive: true, force: true })),
  );
});
test("CLI completes persistent init asset evidence action audit export/import workflow", async () => {
  const { run, dir } = await fixture();
  expect((await run("init", "--name", "Test security")).code).toBe(0);
  expect((await run("init")).code).toBe(2);
  const added = await run(
    "assets",
    "add",
    "--kind",
    "device",
    "--label",
    "Test Mac",
  );
  expect(added.code).toBe(0);
  const assetId = added.data.workspace.assets[0].id;
  const recorded = await run(
    "evidence",
    "add",
    "devices.disk-encryption",
    "--asset",
    assetId,
    "--status",
    "pass",
    "--notes",
    "Verified FileVault is enabled in System Settings today.",
  );
  expect(recorded.code).toBe(0);
  expect(recorded.data.evaluation.score).toBeGreaterThan(0);
  const completed = await run(
    "actions",
    "complete",
    "devices.firewall",
    "--asset",
    assetId,
    "--notes",
    "Enabled firewall and will verify separately.",
  );
  expect(completed.data.workspace.evidence).toHaveLength(1);
  expect(
    completed.data.evaluation.checks.find(
      (c: any) => c.checkId === "devices.firewall",
    ).status,
  ).toBe("unknown");
  expect((await run("audit")).data.workspace.snapshots).toHaveLength(1);
  expect((await run("status")).data.workspace.snapshots).toHaveLength(1);
  const file = join(dir, "export.json");
  expect((await run("export", "--out", file)).code).toBe(0);
  const source = JSON.parse(await readFile(file, "utf8")) as Workspace;
  expect(source.evidence[0]?.method).toBe("guided");
  expect(source.snapshots).toHaveLength(1);
  expect((await stat(file)).mode & 0o777).toBe(0o600);
  const second = await fixture();
  const imported = await second.run("import", file);
  expect(imported.code).toBe(0);
  expect(imported.data.workspace.evidence[0].method).toBe("import");
  expect(imported.data.evaluation.score).toBeNull();
  const reportPath = join(dir, "report.html");
  expect((await run("report", "--out", reportPath)).code).toBe(0);
  const report = await readFile(reportPath, "utf8");
  expect(report).toContain("Security posture");
  expect(report).not.toContain("<script");
});
test("usage failures and missing consent do not mutate workspace", async () => {
  const { run } = await fixture();
  expect((await run("init")).code).toBe(0);
  for (const args of [
    ["scan", "mac"],
    ["scan", "hibp"],
    ["evidence", "add", "missing"],
    ["nonsense"],
    ["audit", "--fail-under", "999"],
  ])
    expect((await run(...args)).code).toBe(2);
  const data = (await run("status")).data;
  expect(data.workspace.evidence).toHaveLength(0);
  expect(data.workspace.snapshots).toHaveLength(0);
  expect((await run("audit", "--fail-under", "80")).code).toBe(2);
  expect((await run("history")).data.snapshots).toHaveLength(1);
});
test("generic evidence cannot forge provider or local trust; invalid check and secret notes fail", async () => {
  const { run } = await fixture();
  await run("init");
  expect(
    (
      await run(
        "evidence",
        "add",
        "bogus",
        "--status",
        "pass",
        "--notes",
        "Verified the imaginary check.",
      )
    ).code,
  ).not.toBe(0);
  expect(
    (
      await run(
        "evidence",
        "add",
        "devices.firewall",
        "--status",
        "pass",
        "--notes",
        "api_key=abcdefghijklmnop",
      )
    ).code,
  ).not.toBe(0);
  expect((await run("status")).data.workspace.evidence).toHaveLength(0);
});
test("version and help work without creating state", async () => {
  const { run } = await fixture();
  expect((await run("--version")).out[0]).toBe("0.1.0");
  expect((await run("--help")).out[0]).toContain("Palisade");
});
test("asset edit retains identity and history while reopening changed identifier evidence", async () => {
  const { run } = await fixture();
  await run("init");
  const added = await run(
    "assets",
    "add",
    "--kind",
    "email",
    "--label",
    "Test email",
    "--value",
    "first@example.test",
  );
  const assetId = added.data.workspace.assets[0].id;
  await run(
    "evidence",
    "add",
    "exposure.breach-review",
    "--asset",
    assetId,
    "--status",
    "pass",
    "--notes",
    "Reviewed the owned email in a breach source and checked its coverage.",
  );
  await run("audit");
  const cosmetic = await run(
    "assets",
    "edit",
    assetId,
    "--label",
    "Renamed email",
    "--not-critical",
  );
  expect(cosmetic.code).toBe(0);
  expect(cosmetic.data.workspace.evidence).toHaveLength(1);
  const updated = await run(
    "assets",
    "edit",
    assetId,
    "--value",
    "second@example.test",
  );
  expect(updated.code).toBe(0);
  expect(updated.data.workspace.assets[0].id).toBe(assetId);
  expect(updated.data.workspace.snapshots).toHaveLength(1);
  expect(updated.data.workspace.evidence.at(-1).status).toBe("unknown");
  expect(
    updated.data.evaluation.checks.find(
      (c: any) => c.checkId === "exposure.breach-review",
    ).earnedPoints,
  ).toBe(0);
});
test("workspace preferences update locally and snapshot deletion requires explicit confirmation", async () => {
  const { run } = await fixture();
  await run("init");
  const changed = await run(
    "workspace",
    "set",
    "--name",
    "Updated audit",
    "--region",
    "CA",
  );
  expect(changed.code).toBe(0);
  expect(changed.data.workspace.name).toBe("Updated audit");
  expect(changed.data.workspace.settings.region).toBe("CA");
  expect((await run("workspace", "set", "--monitoring")).code).toBe(2);
  const first = await run("audit");
  const firstId = first.data.workspace.snapshots[0].id;
  await run("audit");
  expect((await run("audit", "delete", firstId)).code).toBe(2);
  expect((await run("history")).data.snapshots).toHaveLength(2);
  const deleted = await run("audit", "delete", firstId, "--confirm");
  expect(deleted.code).toBe(0);
  expect(deleted.data.workspace.snapshots).toHaveLength(1);
  expect(deleted.data.workspace.evidence).toEqual(
    first.data.workspace.evidence,
  );
});
