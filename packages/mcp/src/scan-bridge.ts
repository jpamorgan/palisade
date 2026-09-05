import { connectScanAgent, scanAgentConfig } from "@palisade/cli/scan-agent";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  GetPromptRequestSchema,
  ListPromptsRequestSchema,
  ListResourcesRequestSchema,
  ListResourceTemplatesRequestSchema,
  ListToolsRequestSchema,
  ReadResourceRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

/** Transparently exposes this scan's current MCP contract without duplicating tool schemas. */
export async function createScanBridge() {
  const config = scanAgentConfig();
  const remote = await connectScanAgent(config);
  const capabilities = remote.client.getServerCapabilities() ?? {};
  const bridge = new Server(
    { name: "palisade-scan-bridge", version: "0.2.0" },
    {
      instructions: remote.client
        .getInstructions()
        ?.split(config.token)
        .join("[redacted]"),
      capabilities: {
        ...(capabilities.tools ? { tools: {} } : {}),
        ...(capabilities.resources ? { resources: {} } : {}),
        ...(capabilities.prompts ? { prompts: {} } : {}),
      },
    },
  );
  if (capabilities.tools) {
    bridge.setRequestHandler(ListToolsRequestSchema, (request) =>
      remote.request((client) => client.listTools(request.params)),
    );
    bridge.setRequestHandler(CallToolRequestSchema, (request, extra) =>
      remote.request((client) =>
        client.callTool(request.params, undefined, { signal: extra.signal }),
      ),
    );
  }
  if (capabilities.resources) {
    bridge.setRequestHandler(ListResourcesRequestSchema, (request) =>
      remote.request((client) => client.listResources(request.params)),
    );
    bridge.setRequestHandler(ListResourceTemplatesRequestSchema, (request) =>
      remote.request((client) => client.listResourceTemplates(request.params)),
    );
    bridge.setRequestHandler(ReadResourceRequestSchema, (request, extra) =>
      remote.request((client) =>
        client.readResource(request.params, { signal: extra.signal }),
      ),
    );
  }
  if (capabilities.prompts) {
    bridge.setRequestHandler(ListPromptsRequestSchema, (request) =>
      remote.request((client) => client.listPrompts(request.params)),
    );
    bridge.setRequestHandler(GetPromptRequestSchema, (request, extra) =>
      remote.request((client) =>
        client.getPrompt(request.params, { signal: extra.signal }),
      ),
    );
  }
  bridge.onclose = () => {
    void remote.close();
  };
  return bridge;
}
