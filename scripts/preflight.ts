import { createCloudflareApi } from "alchemy/cloudflare";

// The existing Alchemy profile is the sole Cloudflare authentication source.
for (const name of [
  "CLOUDFLARE_API_TOKEN",
  "CLOUDFLARE_API_KEY",
  "CLOUDFLARE_EMAIL",
  "CF_API_TOKEN",
  "CF_API_KEY",
]) {
  delete process.env[name];
}
try {
  const api = await createCloudflareApi({ profile: "default" });
  const response = await api.get(
    `/accounts/${api.accountId}/workers/subdomain`,
  );
  if (!response.ok)
    throw new Error(
      `Cloudflare account preflight returned HTTP ${response.status}`,
    );
  const body = (await response.json()) as { result: { subdomain: string } };
  console.log(
    JSON.stringify({
      profile: "default",
      workersSubdomain: body.result.subdomain,
    }),
  );
} catch (error) {
  console.error(
    error instanceof Error ? error.message : "Cloudflare authentication failed",
  );
  process.exitCode = 1;
}
