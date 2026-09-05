/** End-to-end agent handoff using only synthetic data; always deletes its scans. */
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import type { CheckDefinition } from "@palisade/core";

const origin = new URL(process.argv[2] ?? "http://localhost:8787").origin;
if (!origin.startsWith("https:") && !["localhost", "127.0.0.1"].includes(new URL(origin).hostname))
  throw new Error("Smoke tests require HTTPS except on localhost.");
const directory = await mkdtemp(join(tmpdir(), "palisade-scan-smoke-"));
const created: { id: string; ownerToken: string }[] = [];
function assert(value: unknown, message: string): asserts value {
  if (!value) throw new Error(message);
}
async function request(path: string, method = "GET", body?: unknown, token?: string) {
  const response = await fetch(`${origin}${path}`, {
    method, redirect: "error", signal: AbortSignal.timeout(20_000),
    headers: { Origin: origin, ...(body === undefined ? {} : { "Content-Type": "application/json" }), ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await response.text();
  let data: any;
  try { data = JSON.parse(text); } catch { data = text; }
  return { response, data };
}
try {
  const manifest = await request("/agent/manifest.json");
  assert(manifest.response.ok && manifest.data.version === "0.2.0", "Agent manifest unavailable");
  const descriptor = manifest.data.cli;
  assert(/^\/agent\/[a-z.-]+\.js$/.test(descriptor?.url) && /^[a-f0-9]{64}$/.test(descriptor?.sha256), "Invalid bundle manifest");
  const bundle = await fetch(`${origin}${descriptor.url}`, { redirect: "error", signal: AbortSignal.timeout(20_000) });
  assert(bundle.ok, "CLI bundle unavailable");
  const bytes = new Uint8Array(await bundle.arrayBuffer());
  assert(createHash("sha256").update(bytes).digest("hex") === descriptor.sha256, "Downloaded bundle checksum mismatch");
  const cliPath = join(directory, "palisade.js");
  await writeFile(cliPath, bytes, { mode: 0o600 });
  const skill = await request("/agent/skill.md");
  assert(skill.response.ok && typeof skill.data === "string" && skill.data.includes("target.met") && skill.data.includes("HTTPS fallback"), "Audit skill missing or stale");
  const bootstrap = await request("/api/scans", "POST", {});
  assert(bootstrap.response.ok && bootstrap.data.id, "Scan creation failed");
  const scan = bootstrap.data;
  created.push(scan);
  const path = `/api/scans/${scan.id}`;
  assert(scan.viewUrl === `${origin}/scan/${scan.id}#key=${scan.readToken}`, "Private viewing handoff mismatch");
  assert(scan.mcpUrl === `${origin}/mcp/scans/${scan.id}`, "MCP handoff mismatch");
  assert((await request(path)).response.status === 401, "Anonymous scan data exposed");
  const read = await request(path, "GET", undefined, scan.readToken);
  assert(read.response.ok && read.data.evaluation.score === null && read.data.evaluation.coverage === 0 && !read.data.target.met, "Fresh scan fabricated a score");
  assert(read.response.headers.get("cache-control")?.includes("no-store"), "Private response is cacheable");
  assert((await request(`${path}/begin`, "POST", { revision: 0, operationId: crypto.randomUUID() }, scan.readToken)).response.status === 403, "Reader can mutate");
  console.log("PASS: same-origin skill and checksum-verified bundle, private scan handoff and read isolation");

  async function cli(args: string[], input?: unknown) {
    const child = Bun.spawn([process.execPath, cliPath, "scan-agent", ...args], {
      env: { PATH: process.env.PATH ?? "/usr/bin:/bin", PALISADE_SCAN_URL: scan.mcpUrl, PALISADE_AGENT_TOKEN: scan.agentToken },
      stdin: input === undefined ? "ignore" : new Blob([JSON.stringify(input)]), stdout: "pipe", stderr: "pipe",
    });
    const timeout = setTimeout(() => child.kill(), 45_000);
    try {
      const [output, error, code] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
      assert(!output.includes(scan.agentToken) && !error.includes(scan.agentToken), "CLI echoed a credential");
      assert(code === 0, `Detached CLI failed (${code}); no private output logged`);
      return JSON.parse(output);
    } finally { clearTimeout(timeout); }
  }
  const tools = await cli(["tools"]);
  assert(tools.tools.some((t: any) => t.name === "record_evidence") && tools.tools.some((t: any) => t.name === "complete_scan"), "MCP schema discovery failed");
  const call = async (name: string, args?: unknown) => {
    const result = await cli(["call", name, ...(args === undefined ? [] : ["--input", "-"])], args);
    assert(!result.isError, `MCP ${name} failed`);
    return result.structuredContent ?? JSON.parse(result.content[0].text);
  };
  const catalog = await call("get_catalog");
  assert(catalog.categories.length === 8 && catalog.checks.length === 38, "Catalog mismatch");
  let state = await call("get_scan");
  const mutate = async (name: string, args: Record<string, unknown> = {}) => {
    state = await call(name, { revision: state.revision, operationId: crypto.randomUUID(), ...args });
    return state;
  };
  await mutate("begin_scan");
  await mutate("add_asset", { kind: "device", label: "Synthetic smoke device", critical: true });
  const assetId = state.workspace.assets[0].id;
  const check: CheckDefinition = catalog.checks.find((c: CheckDefinition) => c.assetKinds?.includes("device") && c.acceptedMethods.includes("guided"));
  assert(check, "No guided device check");
  const source = { kind: "local_observation", label: "Synthetic integration fixture" };
  await mutate("record_evidence", { checkId: check.id, assetId, status: "fail", notes: "Synthetic test fixture: inspected the test setting and confirmed this control is disabled.", source });
  const before = state.evaluation.score;
  await mutate("record_action", { checkId: check.id, assetId, status: "completed", notes: "Synthetic test fixture: recorded the reversible test change." });
  assert(state.evaluation.score === before, "Completed action granted score credit");
  await mutate("record_evidence", { checkId: check.id, assetId, status: "pass", notes: "Synthetic test fixture: independently rechecked the test control after the change and confirmed it is enabled.", source });
  assert(state.evaluation.score > before && state.evaluation.coverage > 0, "Verified observation failed to improve score");
  assert(!state.target.met, "Partial audit achieved target incorrectly");
  const browserRead = await request(path, "GET", undefined, scan.readToken);
  assert(browserRead.data.revision === state.revision && browserRead.data.evaluation.score === state.evaluation.score, "Browser report did not receive live MCP updates");
  const currentScore = state.evaluation.score;
  await mutate("add_context", { title: "Synthetic public threat context", description: "This is a test headline, not evidence of a personal compromise.", url: "https://www.cisa.gov/news-events", publishedAt: new Date().toISOString() });
  assert(state.evaluation.score === currentScore && state.workspace.threatEvents[0].relevance === "unassessed", "Research changed personal posture");
  await mutate("report_progress", { status: "waiting_for_user", phase: "Review needed", message: "Synthetic audit needs a test-user verification. Independent safe work is complete." });
  assert(state.scan.status === "waiting_for_user", "User blocker not visible");
  await mutate("complete_scan", { summary: "Synthetic audit pass ended below target; remaining checks need verification." });
  assert(state.scan.status === "complete" && !state.target.met && state.workspace.snapshots.length === 1, "Completion confused with target attainment");
  await mutate("begin_scan");
  assert(state.scan.run === 2 && state.workspace.evidence.length === 2, "Re-audit lost evidence or failed to resume");
  console.log("PASS: detached CLI → actual MCP → live report, safe action/verification loop, research context, blockers and re-audit");

  assert((await request(`${path}/agent-token`, "POST", {}, scan.agentToken)).response.status === 403, "Agent can mint a credential");
  assert((await request(path, "DELETE", { confirmation: "DELETE" }, scan.agentToken)).response.status === 403, "Agent can delete a scan");
  const rotated = await request(`${path}/agent-token`, "POST", {}, scan.ownerToken);
  assert(rotated.response.ok && rotated.data.agentToken, "Owner continuation token failed");
  assert((await request(path, "GET", undefined, scan.agentToken)).response.status === 401, "Rotated credential still accepted");
  assert((await request(path, "GET", undefined, rotated.data.agentToken)).response.ok, "Fresh continuation credential rejected");
  console.log("PASS: least-privilege agent, owner continuation and immediate revocation");
} finally {
  let cleanupFailed = false;
  for (const scan of created) {
    try {
      const result = await request(`/api/scans/${scan.id}`, "DELETE", { confirmation: "DELETE" }, scan.ownerToken);
      if (!result.response.ok) cleanupFailed = true;
    } catch { cleanupFailed = true; }
  }
  await rm(directory, { recursive: true, force: true });
  if (cleanupFailed) throw new Error("Synthetic scan cleanup failed; inspect this deployment before rerunning.");
  if (created.length) console.log("PASS: all synthetic scans and temporary bundles deleted");
}
