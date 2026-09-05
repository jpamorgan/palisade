import { parseArgs } from "node:util";
import { open } from "node:fs/promises";
import { constants } from "node:fs";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { PalisadeError, errorInfo } from "./errors";

const MAX_INPUT_BYTES = 65_536;
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const REQUEST_TIMEOUT = 30_000;

export const SCAN_AGENT_HELP = `Palisade scan agent · publish to a live scan from this shell

  palisade scan-agent tools                       Discover tools and JSON schemas
  palisade scan-agent call <tool> [--input -|file] Call a tool (default arguments: {})
  palisade scan-agent read <resource-uri>          Read an advertised MCP resource

Set PALISADE_SCAN_URL to the scan URL without its fragment, or its MCP URL.
Set PALISADE_AGENT_TOKEN in the process environment. Never pass it as an argument.
Tool arguments are a JSON object, read from stdin with --input - or a file (64 KiB max).
Results are JSON. Tools use the same live scan as the web app; no local state is created.
Use your agent's existing search/browser tools for research; no search API key is needed.
After an interrupted write, read get_scan and retry with the SAME operationId to avoid
duplicating observations. An operation failure is not evidence that a write was rolled back.
Exit codes: 0 success; 1 tool/network failure; 2 usage; 3 authentication expired/denied.
`;

export interface ScanAgentConfig {
  endpoint: URL;
  token: string;
}

export function scanAgentConfig(
  env: Record<string, string | undefined> = process.env,
): ScanAgentConfig {
  let url: URL;
  try {
    url = new URL(env.PALISADE_SCAN_URL ?? "");
  } catch {
    throw new PalisadeError(
      "SCAN_URL_REQUIRED",
      "Set PALISADE_SCAN_URL to the scan URL without its #fragment.",
      2,
    );
  }
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(loopback && url.protocol === "http:"))
    throw new PalisadeError(
      "INSECURE_SCAN_URL",
      "Scans require HTTPS. HTTP is allowed only on localhost.",
      2,
    );
  if (url.username || url.password || url.search || url.hash)
    throw new PalisadeError(
      "INVALID_SCAN_URL",
      "The scan URL must have no credentials, query, or fragment. Keep the browser's private viewing key in the browser.",
      2,
    );
  const match = /^\/(?:scan|mcp\/scans)\/([A-Za-z0-9_-]{8,100})\/?$/.exec(
    url.pathname,
  );
  if (!match)
    throw new PalisadeError(
      "INVALID_SCAN_URL",
      "Set PALISADE_SCAN_URL to /scan/<id> or /mcp/scans/<id> on your Palisade host.",
      2,
    );
  const token = env.PALISADE_AGENT_TOKEN;
  if (!token || !/^[A-Za-z0-9._~-]{24,512}$/.test(token))
    throw new PalisadeError(
      "AGENT_TOKEN_REQUIRED",
      "Set PALISADE_AGENT_TOKEN to the private agent token from your copied prompt. Keep it out of commands, notes, and configuration files.",
      2,
    );
  return { endpoint: new URL(`/mcp/scans/${match[1]}`, url.origin), token };
}

/** Removes accidental credential echoes from both successful and failed server responses. */
export function redactScanToken<T>(value: T, token: string): T {
  return JSON.parse(JSON.stringify(value).split(token).join("[redacted]")) as T;
}

function safeScanError(error: unknown): PalisadeError {
  if (error instanceof PalisadeError) return error;
  const code =
    typeof error === "object" && error !== null && "code" in error
      ? error.code
      : undefined;
  if (code === 401 || code === 403)
    return new PalisadeError(
      "SCAN_AUTH_FAILED",
      "The scan agent token was denied or expired. Reconnect from the scan page.",
      3,
    );
  return new PalisadeError(
    "SCAN_REQUEST_FAILED",
    "Could not complete the scan request. Check your connection and use get_scan before retrying a write with the same operationId.",
  );
}

/** The SDK owns protocol negotiation; this boundary owns token and network handling. */
export function scanAgentFetch(
  config: ScanAgentConfig,
  fetcher: typeof fetch = globalThis.fetch,
) {
  return async (input: string | URL, init?: RequestInit): Promise<Response> => {
    if (new URL(String(input)).href !== config.endpoint.href)
      throw new PalisadeError(
        "INVALID_MCP_DESTINATION",
        "Refusing to send a scan token outside its MCP endpoint.",
      );
    const headers = new Headers(init?.headers);
    headers.set("authorization", `Bearer ${config.token}`);
    let response: Response;
    try {
      response = await fetcher(input, {
        ...init,
        headers,
        redirect: "manual",
        signal: AbortSignal.any([
          ...(init?.signal ? [init.signal] : []),
          AbortSignal.timeout(REQUEST_TIMEOUT),
        ]),
      });
    } catch {
      throw safeScanError(undefined);
    }
    if (response.status >= 300 && response.status < 400) {
      await response.body?.cancel();
      throw new PalisadeError(
        "SCAN_REDIRECT_REFUSED",
        "The scan endpoint redirected. No redirect was followed and no token was forwarded.",
      );
    }
    if (!response.ok) {
      await response.body?.cancel();
      // Do not expose error pages: upstream bodies may echo authorization headers.
      return new Response("Scan request rejected.", {
        status: response.status,
      });
    }
    if (!response.body) return response;
    const reader = response.body.getReader();
    let bytes = 0;
    const body = new ReadableStream<Uint8Array>({
      async pull(controller) {
        try {
          const chunk = await reader.read();
          if (chunk.done) return controller.close();
          bytes += chunk.value.byteLength;
          if (bytes > MAX_RESPONSE_BYTES) {
            await reader.cancel();
            return controller.error(
              new PalisadeError(
                "SCAN_RESPONSE_TOO_LARGE",
                "The scan response exceeded 8 MiB.",
              ),
            );
          }
          controller.enqueue(chunk.value);
        } catch {
          controller.error(safeScanError(undefined));
        }
      },
      cancel: (reason) => reader.cancel(reason),
    });
    return new Response(body, {
      status: response.status,
      headers: response.headers,
    });
  };
}

export async function connectScanAgent(config = scanAgentConfig()) {
  const client = new Client({ name: "palisade-scan-agent", version: "0.2.0" });
  const transport = new StreamableHTTPClientTransport(config.endpoint, {
    fetch: scanAgentFetch(config),
    reconnectionOptions: {
      maxRetries: 0,
      initialReconnectionDelay: 1000,
      maxReconnectionDelay: 1000,
      reconnectionDelayGrowFactor: 1,
    },
  });
  try {
    await client.connect(transport, { timeout: REQUEST_TIMEOUT });
  } catch (error) {
    await client.close().catch(() => {});
    throw safeScanError(error);
  }
  return {
    client,
    async request<T>(operation: (client: Client) => Promise<T>): Promise<T> {
      try {
        return redactScanToken(await operation(client), config.token);
      } catch (error) {
        throw safeScanError(error);
      }
    },
    close: () => client.close(),
  };
}

async function readArguments(
  path: string | undefined,
): Promise<Record<string, unknown>> {
  if (path === undefined) return {};
  let text: string;
  if (path === "-") {
    if (process.stdin.isTTY)
      throw new PalisadeError(
        "INPUT_REQUIRED",
        "Pipe a JSON object into --input -.",
        2,
      );
    const chunks: Uint8Array[] = [];
    let bytes = 0;
    const stream = process.stdin;
    const timer = setTimeout(
      () => stream.destroy(new Error("Input timeout")),
      10_000,
    );
    try {
      for await (const chunk of stream) {
        const part =
          typeof chunk === "string" ? Buffer.from(chunk) : (chunk as Buffer);
        bytes += part.byteLength;
        if (bytes > MAX_INPUT_BYTES) throw new Error("Input too large");
        chunks.push(part);
      }
      text = Buffer.concat(chunks).toString("utf8");
    } catch {
      throw new PalisadeError(
        "INVALID_INPUT",
        "Read a JSON object of at most 64 KiB from stdin within 10 seconds.",
        2,
      );
    } finally {
      clearTimeout(timer);
    }
  } else {
    let file;
    try {
      file = await open(
        path,
        constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
      );
      const stat = await file.stat();
      if (!stat.isFile() || stat.size > MAX_INPUT_BYTES)
        throw new Error("Invalid file");
      const buffer = Buffer.alloc(MAX_INPUT_BYTES + 1);
      const { bytesRead } = await file.read(buffer, 0, buffer.byteLength, 0);
      if (bytesRead > MAX_INPUT_BYTES) throw new Error("Input too large");
      text = buffer.subarray(0, bytesRead).toString("utf8");
    } catch {
      throw new PalisadeError(
        "INVALID_INPUT",
        "Input must be a readable regular JSON file of at most 64 KiB.",
        2,
      );
    } finally {
      await file?.close();
    }
  }
  try {
    const value = JSON.parse(text);
    if (value === null || typeof value !== "object" || Array.isArray(value))
      throw new Error("Object required");
    return value;
  } catch {
    throw new PalisadeError(
      "INVALID_INPUT",
      "Tool input must be a valid JSON object.",
      2,
    );
  }
}

export async function runScanAgentCli(
  argv: string[],
  io = {
    stdout: (text: string) => console.log(text),
    stderr: (text: string) => console.error(text),
  },
): Promise<number> {
  try {
    const { values, positionals } = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        input: { type: "string" },
        help: { type: "boolean", short: "h" },
        json: { type: "boolean" },
      },
    });
    if (values.help || !positionals.length) {
      io.stdout(SCAN_AGENT_HELP);
      return 0;
    }
    const [command, target] = positionals;
    if (!(
      (command === "tools" &&
        positionals.length === 1 &&
        values.input === undefined) ||
      (command === "call" &&
        positionals.length === 2 &&
        /^[A-Za-z0-9_.-]{1,100}$/.test(target!)) ||
      (command === "read" &&
        positionals.length === 2 &&
        values.input === undefined &&
        target!.length <= 2048)
    ))
      throw new PalisadeError(
        "USAGE",
        "Use scan-agent tools, call <tool> [--input -|file], or read <resource-uri>.",
        2,
      );
    const input = command === "call" ? await readArguments(values.input) : {};
    const connection = await connectScanAgent();
    try {
      const result = await connection.request(async (client) => {
        if (command === "tools")
          return {
            instructions: client.getInstructions(),
            ...(await client.listTools()),
          };
        if (command === "read") return client.readResource({ uri: target! });
        return client.callTool({ name: target!, arguments: input });
      });
      io.stdout(JSON.stringify(result));
      return "isError" in result && result.isError === true ? 1 : 0;
    } finally {
      await connection.close();
    }
  } catch (error) {
    const info =
      error instanceof PalisadeError
        ? error
        : new PalisadeError(
            "USAGE",
            "Invalid scan-agent arguments. Run palisade scan-agent --help.",
            2,
          );
    io.stderr(JSON.stringify({ error: errorInfo(info) }));
    return info.exitCode;
  }
}
