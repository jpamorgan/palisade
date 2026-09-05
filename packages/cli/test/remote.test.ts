import { expect, test } from "bun:test";
import { RemoteService, normalizeHost } from "../src/remote";
test("remote host validation protects tokens from cleartext and URL confusion", () => {
  for (const value of [
    "http://example.com",
    "https://token@example.com",
    "https://example.com/api",
    "https://example.com?x=1",
    "file:///tmp/a",
    "http://localhost.evil.test",
  ])
    expect(() => normalizeHost(value)).toThrow();
  expect(normalizeHost("http://127.0.0.1:8787/")).toBe("http://127.0.0.1:8787");
  expect(normalizeHost("https://palisade.example")).toBe(
    "https://palisade.example",
  );
});
test("remote calls route correctly without saving credentials or following redirects", async () => {
  let observed: any;
  const client = new RemoteService(
    "https://palisade.example",
    "test-only-token",
    (async (url: string | URL | Request, options?: RequestInit) => {
      observed = { url, options };
      return Response.json({ revision: 2 });
    }) as unknown as typeof fetch,
  );
  expect(await client.request("POST", "/audits", {})).toEqual({ revision: 2 });
  expect(observed.url).toBe("https://palisade.example/api/v1/audits");
  expect(observed.options.redirect).toBe("error");
  expect(observed.options.headers.Authorization).toBe("Bearer test-only-token");
});
test("missing tokens, auth failures and non-JSON errors are explicit", async () => {
  await expect(
    new RemoteService("https://palisade.example", undefined).request(
      "GET",
      "/workspace",
    ),
  ).rejects.toThrow("PALISADE_TOKEN");
  const client = new RemoteService(
    "https://palisade.example",
    "fake",
    (async () =>
      Response.json(
        { error: { code: "UNAUTHORIZED", message: "Token expired." } },
        { status: 401 },
      )) as unknown as typeof fetch,
  );
  await expect(client.request("GET", "/workspace")).rejects.toMatchObject({
    code: "UNAUTHORIZED",
    exitCode: 3,
  });
  const invalid = new RemoteService(
    "https://palisade.example",
    "fake",
    (async () =>
      new Response("<html>bad gateway</html>", {
        status: 502,
      })) as unknown as typeof fetch,
  );
  await expect(invalid.request("GET", "/workspace")).rejects.toThrow(
    "unexpected response",
  );
});
test("upstream bearer echoes and interrupted response bodies do not leak credentials", async () => {
  const token = "test-only-sensitive-token";
  const echo = new RemoteService("https://palisade.example", token, (async () =>
    Response.json(
      { error: { code: "BAD_TOKEN", message: `Rejected ${token}` } },
      { status: 401 },
    )) as unknown as typeof fetch);
  try {
    await echo.request("GET", "/workspace");
    throw new Error("Expected rejection");
  } catch (error) {
    expect((error as Error).message).toContain("[redacted]");
    expect((error as Error).message).not.toContain(token);
  }
  const broken = new RemoteService(
    "https://palisade.example",
    token,
    (async () =>
      new Response(
        new ReadableStream({
          start(controller) {
            controller.error(new Error(`Failed ${token}`));
          },
        }),
      )) as unknown as typeof fetch,
  );
  await expect(broken.request("GET", "/workspace")).rejects.toMatchObject({
    code: "NETWORK_ERROR",
  });
});
