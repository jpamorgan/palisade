import { describe, expect, test } from "bun:test";
import { buildAgentPrompt } from "../apps/web/src/agent-prompt";

describe("agent handoff boundaries", () => {
  test("handoff is scoped to the supplied origin/scan and never includes owner authority", () => {
    const bootstrap = {
      id: "scan-synthetic-id", agentToken: "agent-synthetic-token-for-this-scan",
      ownerToken: "owner-synthetic-must-never-be-shared",
      viewUrl: "https://audit.example.test/scan/scan-synthetic-id#key=reader-synthetic",
      mcpUrl: "https://audit.example.test/mcp/scans/scan-synthetic-id",
      expiresAt: "2026-10-01T00:00:00.000Z", agentExpiresAt: "2026-09-08T00:00:00.000Z",
    };
    for (const mode of ["start", "continue"] as const) {
      const prompt = buildAgentPrompt(bootstrap, mode);
      expect(prompt).toContain(bootstrap.viewUrl);
      expect(prompt).toContain(bootstrap.mcpUrl);
      expect(prompt).toContain(`Authorization: Bearer ${bootstrap.agentToken}`);
      expect(prompt).not.toContain(bootstrap.ownerToken);
      expect(prompt).toContain("https://audit.example.test/agent/skill.md");
      expect(prompt).toContain("https://audit.example.test/agent/manifest.json");
      expect(prompt).not.toContain("palisade.jpamorgan.workers.dev");
    }
  });
});
