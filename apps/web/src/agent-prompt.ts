export interface AgentPromptInput {
  id: string;
  agentToken: string;
  viewUrl: string;
  mcpUrl: string;
  expiresAt: string;
  agentExpiresAt: string;
}

/** Only scan-scoped agent and reader capabilities belong in the handoff. */
export function buildAgentPrompt(
  input: AgentPromptInput,
  mode: "start" | "continue" = "start",
): string {
  const origin = new URL(input.mcpUrl).origin;
  return `${mode === "continue" ? "Continue" : "Run"} my personal security audit with Palisade. Do the research and verification with your existing tools, publish results live, and iteratively implement safe authorized fixes. Begin in this conversation; do not stop after MCP setup or a list of suggestions.

First read and follow the audit skill: ${origin}/agent/skill.md
You can use the instructions directly; install the skill only if your agent requires it.

Private live report: ${input.viewUrl}
Scan ID: ${input.id}
MCP endpoint: ${input.mcpUrl}
Authorization: Bearer ${input.agentToken}
Agent access expires: ${input.agentExpiresAt}
Scan expires: ${input.expiresAt}

Connect with the bearer token above. If your MCP client cannot add a connection without restarting, continue immediately using the standalone CLI: fetch ${origin}/agent/manifest.json, download its CLI bundle, verify the SHA-256, and run it with Bun. Set PALISADE_SCAN_URL to the MCP endpoint and PALISADE_AGENT_TOKEN to the token in the subprocess environment. Discover tools with "bun palisade.js scan-agent tools"; invoke them with "bun palisade.js scan-agent call TOOL --input -" and JSON on stdin. If Bun is unavailable, use the skill's equivalent HTTPS API with your existing HTTP tool. Do not let installation block the audit.

Read get_catalog and get_scan, then begin_scan. Show me the private report link immediately. Publish concise progress and verified evidence after each useful step so I can watch the page update. Use the returned revision and a fresh UUID operationId on each mutation. Keep credentials out of notes, logs, URLs sent to providers, and files in repositories.

Use your existing web search, browser, connectors and local tools. No Brave API key is needed. Audit only my owned or authorized assets; use existing context and ask only for missing information. Obtain any needed identifier-disclosure consent. Public news or namesake search results are context, never proof that I was compromised.

Loop: verify an important gap, implement the smallest clearly safe reversible fix within my authorization, independently re-verify it, record the observation, and choose the next action. Continue independent safe work while other checks are blocked. The default deterministic target is score >=85/100, coverage >=90%, and zero critical findings: use the server's target.met. Never game applicability, omit assets, fabricate evidence, or treat completed actions as verified protection. Pause changes that risk lockout, loss, interruption, spending, external disclosure or require a new decision; tell me the specific blocker and continue other safe work.

When the target is reached, complete_scan and summarize the verified improvements. If safe work is exhausted first, report waiting_for_user or blocked with the exact next steps; do not claim success or loop endlessly. Finish with score, coverage, remaining actions and the private report link.`;
}
