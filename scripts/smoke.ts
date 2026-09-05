/** Creates only synthetic data and deletes the entire test account in finally. */
export {};
const origin = new URL(process.argv[2] ?? "http://localhost:8787").origin;
if (
  !origin.startsWith("https:") &&
  !["localhost", "127.0.0.1"].includes(new URL(origin).hostname)
) {
  throw new Error("Smoke tests require HTTPS except on localhost.");
}
const cookies = new Map<string, string>();
const email = `palisade-smoke-${crypto.randomUUID()}@example.test`;
const password = `Test-${crypto.randomUUID()}-only!`;
let created = false;
function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}
async function request(
  path: string,
  method = "GET",
  body?: unknown,
  token?: string,
) {
  const headers: Record<string, string> = { Origin: origin };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers.Authorization = `Bearer ${token}`;
  else if (cookies.size)
    headers.Cookie = [...cookies].map(([k, v]) => `${k}=${v}`).join("; ");
  const response = await fetch(`${origin}${path}`, {
    method,
    headers,
    redirect: "error",
    signal: AbortSignal.timeout(60_000),
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  for (const cookie of response.headers.getSetCookie()) {
    const pair = cookie.split(";")[0]!,
      split = pair.indexOf("=");
    const name = pair.slice(0, split),
      value = pair.slice(split + 1);
    if (value) cookies.set(name, value);
    else cookies.delete(name);
  }
  const content = await response.text();
  let data: any;
  try {
    data = JSON.parse(content);
  } catch {
    data = content;
  }
  return { response, data };
}
try {
  assert((await request("/api/health")).data.ok, "Health failed");
  const catalog = await request("/api/v1/catalog");
  assert(
    catalog.data.categories.length === 8 && catalog.data.checks.length >= 32,
    "Catalog missing",
  );
  assert(
    (await request("/api/v1/workspace")).response.status === 401,
    "Anonymous workspace exposed",
  );
  const signup = await request("/api/auth/sign-up/email", "POST", {
    name: "Synthetic Release Check",
    email,
    password,
  });
  assert(
    signup.response.status === 200,
    `Signup failed (${signup.response.status})`,
  );
  created = true;
  console.log("PASS: public catalog, private boundary, account registration");
  let state = await request("/api/v1/assets", "POST", {
    kind: "email",
    label: "Synthetic email",
    value: email,
    critical: true,
  });
  assert(state.response.status === 200, "Asset persistence failed");
  const assetId = state.data.workspace.assets[0].id;
  const check = catalog.data.checks.find(
    (c: any) =>
      c.assetKinds?.includes("email") && c.acceptedMethods.includes("guided"),
  );
  state = await request("/api/v1/evidence", "POST", {
    checkId: check.id,
    assetId,
    status: "fail",
    notes: "Synthetic integration fixture: this control has not been enabled.",
  });
  assert(state.response.status === 200, "Evidence persistence failed");
  const score = state.data.evaluation.score;
  state = await request("/api/v1/actions", "POST", {
    checkId: check.id,
    assetId,
    status: "completed",
  });
  assert(
    state.data.evaluation.score === score,
    "Action incorrectly changed score",
  );
  state = await request("/api/v1/evidence", "POST", {
    checkId: check.id,
    assetId,
    status: "pass",
    notes:
      "Synthetic integration fixture: confirmed control in test account settings.",
  });
  assert(
    state.data.evaluation.score > score,
    "Verified evidence failed to improve score",
  );
  state = await request("/api/v1/audits", "POST", {});
  assert(state.data.workspace.snapshots.length === 1, "Snapshot failed");
  const exportResult = await request("/api/v1/export");
  assert(exportResult.data.evidence.length === 2, "Export missing evidence");
  console.log(
    "PASS: D1 audit persistence, deterministic score, mitigation separation, export",
  );
  const token = await request("/api/v1/tokens", "POST", {
    name: "Synthetic smoke reader",
    scopes: ["read"],
  });
  assert(token.response.status === 200, "Token creation failed");
  assert(
    (await request("/api/v1/workspace", "GET", undefined, token.data.token))
      .response.status === 200,
    "Token read failed",
  );
  assert(
    (await request("/api/v1/assets", "POST", {}, token.data.token)).response
      .status === 403,
    "Read token allowed write",
  );
  const mcpResponse = await fetch(`${origin}/mcp`, {
    method: "POST",
    redirect: "error",
    signal: AbortSignal.timeout(60_000),
    headers: {
      Authorization: `Bearer ${token.data.token}`,
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "get_workspace", arguments: {} },
    }),
  });
  const mcp = (await mcpResponse.json()) as any;
  assert(
    mcpResponse.status === 200 &&
      !mcp.result?.isError &&
      mcp.result?.content?.[0]?.text.includes("coverage"),
    "Hosted MCP failed",
  );
  console.log("PASS: hosted scoped tokens and MCP tool exchange");
  const feeds = await request("/api/v1/scans/threats", "POST", {});
  assert(
    feeds.response.status === 200 &&
      feeds.data.workspace.threatEvents.length > 0,
    `Live public feed refresh failed (${feeds.response.status}): ${feeds.data.error?.message ?? feeds.data.receipt?.message ?? "No events returned"} ${JSON.stringify(feeds.data.receipt?.sources ?? [])}`,
  );
  console.log(`PASS: public threat feeds (${feeds.data.receipt.status})`);
  const integrations = await request("/api/v1/integrations");
  if (integrations.data.assistant?.available) {
    const answer = await request("/api/v1/assistant", "POST", {
      checkId: check.id,
      message: "What should I verify before changing this sign-in protection?",
    });
    assert(
      answer.response.status === 200 && answer.data.answer?.length > 20,
      `Workers AI guide failed (${answer.response.status}): ${answer.data.error?.message ?? "No answer returned"}`,
    );
    console.log("PASS: Cloudflare Workers AI guidance");
  }
  const current = await request("/api/v1/workspace");
  const monitoring = await request("/api/v1/workspace", "PATCH", {
    settings: { monitoring: true },
    revision: current.data.revision,
  });
  assert(
    monitoring.response.status === 200 &&
      monitoring.data.workspace.settings.monitoring,
    "Monitoring opt-in failed",
  );
  const removed = await request(
    `/api/v1/audits/${state.data.workspace.snapshots[0].id}`,
    "DELETE",
    { confirmation: "DELETE" },
  );
  assert(
    removed.response.status === 200 &&
      removed.data.workspace.snapshots.length === 0 &&
      removed.data.workspace.evidence.length >= 2,
    "History removal failed",
  );
  console.log("PASS: monitoring preferences and history management");
} finally {
  if (created) {
    const cleanup = await request("/api/auth/delete-user", "POST", {
      password,
    });
    assert(
      cleanup.response.status === 200,
      `Synthetic account cleanup failed (${cleanup.response.status}); remove the synthetic smoke account from the test deployment`,
    );
    console.log("PASS: synthetic account and all private data removed");
  }
}
