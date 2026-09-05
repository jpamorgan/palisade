import { describe, expect, test } from "bun:test";
import {
  addAsset,
  applyFootprintResult,
  applyHibpResult,
  applyThreatFeedResult,
  checkHibp,
  createWorkspace,
  evaluateWorkspace,
  fetchThreatFeeds,
  searchFootprint,
  WorkspaceSchema,
  updateAsset,
} from "./index";
const NOW = "2026-09-04T12:00:00.000Z",
  KEY = "0123456789abcdef0123456789abcdef";
const breach = {
  Name: "ExampleBreach",
  Title: "Example service",
  Domain: "example.test",
  BreachDate: "2025-01-01",
  AddedDate: "2026-09-01T00:00:00Z",
  DataClasses: ["Email addresses", "Passwords"],
  IsVerified: true,
};
const kev = {
  vulnerabilities: [
    {
      cveID: "CVE-2026-12345",
      vendorProject: "Example",
      product: "Example appliance",
      vulnerabilityName: "Example issue",
      dateAdded: "2026-09-03",
      shortDescription: "A synthetic test issue.",
      requiredAction: "Apply vendor updates.",
    },
  ],
};
function mockFetch(
  handler: (url: string, init?: RequestInit) => Promise<Response> | Response,
): typeof fetch {
  return ((url: RequestInfo | URL, init?: RequestInit) =>
    Promise.resolve(handler(String(url), init))) as typeof fetch;
}
function workspace() {
  return addAsset(
    createWorkspace("Provider test", NOW),
    {
      kind: "email",
      label: "Owned email",
      value: "owner@example.test",
      critical: true,
    },
    NOW,
  );
}
describe("authorized bounded HIBP adapter", () => {
  test("missing consent, ownership or credential sends no request", async () => {
    let calls = 0;
    const fetch = mockFetch(() => {
      calls++;
      return new Response("[]");
    });
    for (const options of [
      { consent: false, ownershipVerified: true },
      { consent: true, ownershipVerified: false },
    ])
      expect(
        (
          await checkHibp("owner@example.test", KEY, {
            ...options,
            fetch,
            now: NOW,
          })
        ).receipt.status,
      ).toBe("unavailable");
    expect(
      (
        await checkHibp("owner@example.test", "", {
          consent: true,
          ownershipVerified: true,
          fetch,
          now: NOW,
        })
      ).receipt.status,
    ).toBe("unavailable");
    expect(calls).toBe(0);
  });
  test("URL encodes owned email and sends key only in header with redirects prohibited", async () => {
    let called = "",
      headers: Headers | undefined;
    const response = await checkHibp("owner+tag@example.test", KEY, {
      consent: true,
      ownershipVerified: true,
      now: NOW,
      fetch: mockFetch((url, init) => {
        called = url;
        headers = new Headers(init?.headers);
        expect(init?.redirect).toBe("manual");
        return Response.json([breach]);
      }),
    });
    expect(called).toContain("owner%2Btag%40example.test");
    expect(called).not.toContain(KEY);
    expect(headers!.get("hibp-api-key")).toBe(KEY);
    expect(response.breaches[0]!.dataClasses).toContain("Passwords");
    expect(response.receipt.status).toBe("ok");
  });
  test("404 is an explicitly coverage-limited no-match, not no leakage", async () => {
    const result = await checkHibp("owner@example.test", KEY, {
      consent: true,
      ownershipVerified: true,
      now: NOW,
      fetch: mockFetch(() => new Response(null, { status: 404 })),
    });
    expect(result.receipt.status).toBe("ok");
    expect(result.receipt.message).toContain("does not establish");
    expect(result.scope).toContain("sensitive and retired");
  });
  test("provider failure and malformed data never become clean results", async () => {
    for (const response of [
      new Response(null, { status: 500 }),
      Response.json({ unexpected: true }),
      new Response("not-json"),
      new Response("[]", { headers: { "content-length": "9000000" } }),
    ]) {
      const result = await checkHibp("owner@example.test", KEY, {
        consent: true,
        ownershipVerified: true,
        now: NOW,
        fetch: mockFetch(() => response),
      });
      expect(result.receipt.status).not.toBe("ok");
      expect(result.breaches).toEqual([]);
    }
  });
  test("timeouts cover stalled request and stalled streaming bodies", async () => {
    for (const fetch of [
      mockFetch(() => new Promise(() => {})),
      mockFetch(() => new Response(new ReadableStream({ start() {} }))),
    ]) {
      const start = Date.now();
      const result = await checkHibp("owner@example.test", KEY, {
        consent: true,
        ownershipVerified: true,
        now: NOW,
        fetch,
        timeoutMs: 50,
      });
      expect(result.receipt.status).toBe("unavailable");
      expect(Date.now() - start).toBeLessThan(1000);
    }
  });
  test("rate limits preserve bounded retry guidance without echoing private response bodies", async () => {
    const result = await checkHibp("owner@example.test", KEY, {
      consent: true,
      ownershipVerified: true,
      now: NOW,
      fetch: mockFetch(
        () =>
          new Response(`Private API key ${KEY}`, {
            status: 429,
            headers: { "retry-after": "30" },
          }),
      ),
    });
    expect(result.receipt.retryAfterSeconds).toBe(30);
    expect(JSON.stringify(result)).not.toContain(KEY);
  });
  test("historical breaches pass the review only and retain exposure separately", async () => {
    const w = workspace(),
      result = await checkHibp("owner@example.test", KEY, {
        consent: true,
        ownershipVerified: true,
        now: NOW,
        fetch: mockFetch(() => Response.json([breach])),
      }),
      updated = applyHibpResult(w, w.assets[0]!.id, result, NOW),
      evaluation = evaluateWorkspace(updated, NOW);
    expect(updated.threatEvents[0]!.relevance).toBe("confirmed");
    expect(
      evaluation.checks.find((c) => c.checkId === "exposure.breach-review")!
        .status,
    ).toBe("pass");
    expect(
      evaluation.checks.find(
        (c) => c.checkId === "exposure.credential-response",
      )!.status,
    ).toBe("unknown");
    expect(w.evidence).toEqual([]);
    expect(WorkspaceSchema.safeParse(updated).success).toBe(true);
  });
  test("unavailable scan emits unknown evidence and does not erase past breach events", async () => {
    const w = workspace(),
      good = await checkHibp("owner@example.test", KEY, {
        consent: true,
        ownershipVerified: true,
        now: NOW,
        fetch: mockFetch(() => Response.json([breach])),
      }),
      first = applyHibpResult(w, w.assets[0]!.id, good, NOW);
    const later = "2026-09-04T13:00:00.000Z",
      bad = await checkHibp("owner@example.test", KEY, {
        consent: true,
        ownershipVerified: true,
        now: later,
        fetch: mockFetch(() => new Response(null, { status: 503 })),
      }),
      second = applyHibpResult(first, w.assets[0]!.id, bad, later);
    expect(second.threatEvents.length).toBe(1);
    expect(
      evaluateWorkspace(second, later).checks.find(
        (c) => c.checkId === "exposure.breach-review",
      )!.status,
    ).toBe("unknown");
  });
});
describe("public threat and search context", () => {
  test("default fetch keeps its global receiver and uses Workers-compatible manual redirects", async () => {
    const originalFetch = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = function (
      this: unknown,
      url: RequestInfo | URL,
      init?: RequestInit,
    ) {
      if (this !== globalThis) throw new TypeError("Illegal invocation");
      if (init?.redirect !== "manual")
        throw new TypeError("Invalid redirect value");
      calls++;
      return Promise.resolve(
        Response.json(String(url).includes("cisa.gov") ? kev : [breach]),
      );
    } as typeof fetch;
    try {
      const feed = await fetchThreatFeeds({ now: NOW });
      expect(feed.receipt.status).toBe("ok");
      expect(feed.events.length).toBe(2);
      expect(calls).toBe(2);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
  test("provider redirects stay unassessed and never trigger a second credential-bearing request", async () => {
    let calls = 0;
    const fetch = mockFetch((_url, init) => {
      calls++;
      expect(init?.redirect).toBe("manual");
      return new Response(null, {
        status: 302,
        headers: { location: "https://untrusted.example.test/collect" },
      });
    });
    const hibp = await checkHibp("owner@example.test", KEY, {
      consent: true,
      ownershipVerified: true,
      now: NOW,
      fetch,
    });
    const footprint = await searchFootprint("Example Person", "secret", {
      consent: true,
      now: NOW,
      fetch,
    });
    const feed = await fetchThreatFeeds({ now: NOW, fetch });
    expect(calls).toBe(4);
    expect(hibp.receipt.status).not.toBe("ok");
    expect(hibp.breaches).toEqual([]);
    expect(footprint.receipt.status).not.toBe("ok");
    expect(footprint.results).toEqual([]);
    expect(feed.events).toEqual([]);
    expect(
      feed.receipt.sources?.every(
        (source) => source.httpStatus === 302 && source.code === "http_error",
      ),
    ).toBe(true);
  });
  test("CISA and breach catalog events are unassessed and do not alter posture", async () => {
    const feed = await fetchThreatFeeds({
      now: NOW,
      fetch: mockFetch((url) =>
        Response.json(url.includes("cisa.gov") ? kev : [breach]),
      ),
    });
    expect(feed.receipt.status).toBe("ok");
    expect(feed.receipt.sources).toEqual([
      { source: "cisa", status: "ok", httpStatus: 200 },
      { source: "hibp", status: "ok", httpStatus: 200 },
    ]);
    expect(feed.events.length).toBe(2);
    expect(feed.events.every((e) => e.relevance === "unassessed")).toBe(true);
    const w = createWorkspace("Feeds", NOW),
      updated = applyThreatFeedResult(w, feed, NOW);
    expect(evaluateWorkspace(updated, NOW)).toEqual(evaluateWorkspace(w, NOW));
    expect(applyThreatFeedResult(updated, feed, NOW).threatEvents.length).toBe(
      2,
    );
  });
  test("partial feed outage preserves available reports and explicitly marks incomplete coverage", async () => {
    const feed = await fetchThreatFeeds({
      now: NOW,
      fetch: mockFetch((url) =>
        url.includes("cisa.gov")
          ? Response.json(kev)
          : new Response(null, { status: 503 }),
      ),
    });
    expect(feed.events.length).toBe(1);
    expect(feed.receipt.status).toBe("unavailable");
    expect(feed.receipt.message).toContain("incomplete source coverage");
    expect(feed.receipt.sources).toEqual([
      { source: "cisa", status: "ok", httpStatus: 200 },
      {
        source: "hibp",
        status: "unavailable",
        httpStatus: 503,
        code: "http_error",
        errorName: "Error",
      },
    ]);
  });
  test("public source diagnostics distinguish runtime failures without echoing arbitrary exception text", async () => {
    const secret = "private-identifier-and-credential";
    const feed = await fetchThreatFeeds({
      now: NOW,
      fetch: mockFetch((url) => {
        if (url.includes("cisa.gov"))
          throw new TypeError(`Illegal invocation: ${secret}`);
        const error = new Error(secret);
        error.name = secret;
        throw error;
      }),
    });
    expect(feed.receipt.sources).toEqual([
      {
        source: "cisa",
        status: "unavailable",
        code: "illegal_invocation",
        errorName: "TypeError",
      },
      {
        source: "hibp",
        status: "unavailable",
        code: "unknown_error",
        errorName: "Error",
      },
    ]);
    expect(JSON.stringify(feed)).not.toContain(secret);
    expect(feed.events).toEqual([]);
  });
  test("public source diagnostics identify bounded parsing and response failures", async () => {
    const cases = [
      {
        response: () => new Response("private invalid JSON"),
        code: "invalid_json",
      },
      {
        response: () => Response.json({ private: "invalid schema" }),
        code: "invalid_schema",
      },
      { response: () => new Response(null), code: "empty_response" },
      {
        response: () =>
          new Response("private oversized body", {
            headers: { "content-length": "8000001" },
          }),
        code: "response_too_large",
      },
      {
        response: () =>
          new Response("private rejected response", { status: 403 }),
        code: "http_error",
      },
    ];
    for (const item of cases) {
      const feed = await fetchThreatFeeds({
        now: NOW,
        fetch: mockFetch(item.response),
      });
      expect(feed.receipt.sources?.length).toBe(2);
      expect(
        feed.receipt.sources?.every(
          (source) =>
            source.code === item.code && source.status === "unavailable",
        ),
      ).toBe(true);
      expect(JSON.stringify(feed)).not.toContain("private");
    }
    const timeout = await fetchThreatFeeds({
      now: NOW,
      timeoutMs: 50,
      fetch: mockFetch(() => new Promise(() => {})),
    });
    expect(
      timeout.receipt.sources?.every((source) => source.code === "timeout"),
    ).toBe(true);
  });
  test("Brave requires consent and a configured key and malformed response is not an empty success", async () => {
    let calls = 0;
    const fetch = mockFetch(() => {
      calls++;
      return Response.json({});
    });
    expect(
      (
        await searchFootprint("Example Person", "key", {
          consent: false,
          fetch,
          now: NOW,
        })
      ).receipt.status,
    ).toBe("unavailable");
    expect(
      (
        await searchFootprint("Example Person", "", {
          consent: true,
          fetch,
          now: NOW,
        })
      ).receipt.status,
    ).toBe("unavailable");
    expect(calls).toBe(0);
    expect(
      (
        await searchFootprint("Example Person", "key", {
          consent: true,
          fetch,
          now: NOW,
        })
      ).receipt.status,
    ).toBe("unavailable");
  });
  test("search strips HTML, excludes unsafe URLs, keeps same-domain pages distinct and never confirms identity", async () => {
    const result = await searchFootprint("Example Person", "key", {
      consent: true,
      now: NOW,
      fetch: mockFetch((url, init) => {
        expect(new URL(url).hostname).toBe("api.search.brave.com");
        expect(new Headers(init?.headers).get("x-subscription-token")).toBe(
          "key",
        );
        return Response.json({
          query: { original: "Example Person" },
          web: {
            results: [
              {
                url: "https://example.test/a/very/long/shared/path/one",
                title: "<b>Example</b>",
                description: "<script>test</script> profile",
              },
              {
                url: "https://example.test/a/very/long/shared/path/two",
                title: "Other page",
              },
              { url: "javascript:alert(1)", title: "Bad" },
              { url: "https://127.0.0.1/private", title: "Local" },
            ],
          },
        });
      }),
    });
    expect(result.results.length).toBe(2);
    expect(result.results[0]!.title).toBe("Example");
    const w = addAsset(
        workspace(),
        { kind: "identity", label: "Example Person", critical: false },
        NOW,
      ),
      updated = applyFootprintResult(w, w.assets.at(-1)!.id, result, NOW);
    expect(updated.threatEvents.length).toBe(2);
    expect(
      updated.threatEvents.every((e) => e.relevance === "unassessed"),
    ).toBe(true);
    expect(evaluateWorkspace(updated, NOW).score).toBeNull();
    expect(
      applyFootprintResult(updated, w.assets.at(-1)!.id, result, NOW)
        .threatEvents.length,
    ).toBe(2);
  });
  test("in-flight provider results cannot be applied after their scoped identifier changes", async () => {
    const w = workspace(),
      assetId = w.assets[0]!.id;
    const hibp = await checkHibp("owner@example.test", KEY, {
      consent: true,
      ownershipVerified: true,
      now: NOW,
      fetch: mockFetch(() => Response.json([breach])),
    });
    const edited = updateAsset(
      w,
      assetId,
      { value: "replacement@example.test" },
      "2026-09-04T12:00:01.000Z",
    );
    expect(() =>
      applyHibpResult(edited, assetId, hibp, "2026-09-04T12:00:02.000Z"),
    ).toThrow("identifier changed");
    expect(edited.threatEvents).toEqual([]);
    const named = addAsset(
        w,
        { kind: "identity", label: "Example Person", critical: false },
        NOW,
      ),
      nameId = named.assets.at(-1)!.id;
    const search = await searchFootprint("Example Person", "key", {
      consent: true,
      now: NOW,
      fetch: mockFetch(() =>
        Response.json({
          query: { original: "Example Person" },
          web: {
            results: [
              { url: "https://example.test/profile", title: "Profile" },
            ],
          },
        }),
      ),
    });
    const renamed = updateAsset(
      named,
      nameId,
      { label: "Different Person" },
      "2026-09-04T12:00:01.000Z",
    );
    expect(() =>
      applyFootprintResult(renamed, nameId, search, "2026-09-04T12:00:02.000Z"),
    ).toThrow("identifier changed");
  });
  test("a new authorized scan after an identifier edit preserves old matches and confirms current matches separately", async () => {
    const w = workspace(),
      assetId = w.assets[0]!.id;
    const original = await checkHibp("owner@example.test", KEY, {
      consent: true,
      ownershipVerified: true,
      now: NOW,
      fetch: mockFetch(() => Response.json([breach])),
    });
    const first = applyHibpResult(w, assetId, original, NOW),
      changed = updateAsset(
        first,
        assetId,
        { value: "replacement@example.test" },
        "2026-09-04T12:00:01.000Z",
      );
    const current = await checkHibp("replacement@example.test", KEY, {
      consent: true,
      ownershipVerified: true,
      now: "2026-09-04T12:00:02.000Z",
      fetch: mockFetch(() => Response.json([breach])),
    });
    const updated = applyHibpResult(
      changed,
      assetId,
      current,
      "2026-09-04T12:00:03.000Z",
    );
    expect(updated.threatEvents).toHaveLength(2);
    expect(
      updated.threatEvents.find((e) => e.id === first.threatEvents[0]!.id)!
        .relevance,
    ).toBe("unassessed");
    expect(
      updated.threatEvents.filter((e) => e.relevance === "confirmed"),
    ).toHaveLength(1);
    expect(
      evaluateWorkspace(updated, "2026-09-04T12:00:03.000Z").checks.find(
        (c) => c.checkId === "exposure.breach-review",
      )!.status,
    ).toBe("pass");
    expect(updated.updatedAt).toBe("2026-09-04T12:00:03.000Z");
  });
});
