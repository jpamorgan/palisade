import { expect, test } from "bun:test";
import {
  scanAgentConfig,
  scanAgentFetch,
  runScanAgentCli,
} from "../src/scan-agent";

const token = "pal_synthetic_scan_token_123456789012345678901234";
const env = {
  PALISADE_SCAN_URL:
    "https://palisade.example/scan/00000000-0000-4000-8000-000000000001",
  PALISADE_AGENT_TOKEN: token,
};

test("scan agent URLs isolate a single endpoint and never accept browser read keys", () => {
  expect(scanAgentConfig(env).endpoint.href).toBe(
    "https://palisade.example/mcp/scans/00000000-0000-4000-8000-000000000001",
  );
  expect(
    scanAgentConfig({
      ...env,
      PALISADE_SCAN_URL: "http://127.0.0.1:8787/mcp/scans/00000000",
    }).endpoint.port,
  ).toBe("8787");
  for (const url of [
    "http://palisade.example/scan/00000000",
    "http://localhost.evil.example/scan/00000000",
    "https://palisade.example/scan/00000000#key=secret",
    "https://palisade.example/scan/00000000?token=secret",
    "https://secret@palisade.example/scan/00000000",
    "https://palisade.example/api/scans/00000000",
    "https://palisade.example/scan/%2F..%2Fsecrets",
  ])
    expect(() => scanAgentConfig({ ...env, PALISADE_SCAN_URL: url })).toThrow();
  expect(() =>
    scanAgentConfig({ ...env, PALISADE_AGENT_TOKEN: undefined }),
  ).toThrow("PALISADE_AGENT_TOKEN");
  expect(() =>
    scanAgentConfig({
      ...env,
      PALISADE_AGENT_TOKEN: token + "\r\nHeader: injected",
    }),
  ).toThrow();
});

test("scan transport refuses redirects and endpoint changes without forwarding credentials", async () => {
  const config = scanAgentConfig(env);
  const seen: RequestInit[] = [];
  const fetcher = scanAgentFetch(config, (async (
    _input: string | URL | Request,
    init?: RequestInit,
  ) => {
    seen.push(init!);
    return new Response(null, {
      status: 307,
      headers: { location: "https://other.example" },
    });
  }) as unknown as typeof fetch);
  await expect(fetcher(config.endpoint, { method: "POST" })).rejects.toThrow(
    "No redirect was followed",
  );
  expect(seen).toHaveLength(1);
  expect(seen[0]!.redirect).toBe("manual");
  expect(new Headers(seen[0]!.headers).get("authorization")).toBe(
    `Bearer ${token}`,
  );
  await expect(
    fetcher("https://other.example/mcp/scans/00000000"),
  ).rejects.toThrow("outside its MCP endpoint");
  expect(seen).toHaveLength(1);
});

test("transport discards upstream error bodies and bounds successful bodies", async () => {
  const config = scanAgentConfig(env);
  const rejected = scanAgentFetch(
    config,
    (async () =>
      new Response(`rejected ${token}`, {
        status: 403,
      })) as unknown as typeof fetch,
  );
  expect(await (await rejected(config.endpoint)).text()).not.toContain(token);
  const oversized = scanAgentFetch(
    config,
    (async () =>
      new Response(
        new Uint8Array(8 * 1024 * 1024 + 1),
      )) as unknown as typeof fetch,
  );
  await expect((await oversized(config.endpoint)).text()).rejects.toThrow(
    "8 MiB",
  );
  const broken = scanAgentFetch(config, (async () => {
    throw new Error(token);
  }) as unknown as typeof fetch);
  await expect(broken(config.endpoint)).rejects.toThrow("Could not complete");
});

test("scan CLI help works without credentials and unknown flags never echo their values", async () => {
  const stdout: string[] = [],
    stderr: string[] = [];
  const io = {
    stdout: (value: string) => stdout.push(value),
    stderr: (value: string) => stderr.push(value),
  };
  expect(await runScanAgentCli(["--help"], io)).toBe(0);
  expect(stdout.join("")).toContain("--input -");
  expect(await runScanAgentCli(["tools", "--token", token], io)).toBe(2);
  expect(stderr.join("")).not.toContain(token);
  expect(await runScanAgentCli(["call", token, "extra"], io)).toBe(2);
  expect(stderr.join("")).not.toContain(token);
});
