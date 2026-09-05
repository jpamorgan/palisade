import alchemy from "alchemy";
import {
  Assets,
  Ai,
  D1Database,
  EmailSender,
  Queue,
  Worker,
  createCloudflareApi,
} from "alchemy/cloudflare";
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

// Authentication is exclusively through the existing global default profile.
for (const name of [
  "CLOUDFLARE_API_TOKEN",
  "CLOUDFLARE_API_KEY",
  "CLOUDFLARE_EMAIL",
  "CF_API_TOKEN",
  "CF_API_KEY",
]) {
  delete process.env[name];
}
let secrets: Record<string, string> = {};
try {
  secrets = JSON.parse(
    await readFile(
      join(homedir(), ".config", "palisade", "deployment.json"),
      "utf8",
    ),
  );
} catch {}
const secret = (name: string) => {
  const value = process.env[name] ?? secrets[name];
  if (!value || value.length < 32)
    throw new Error(
      `Missing ${name}. Run bun scripts/setup.ts or configure the application secret.`,
    );
  return value;
};
const app = await alchemy("palisade", {
  profile: "default",
  password: secret("ALCHEMY_PASSWORD"),
});
const api = await createCloudflareApi({ profile: "default" });
const subdomainResponse = await api.get(
  `/accounts/${api.accountId}/workers/subdomain`,
);
if (!subdomainResponse.ok)
  throw new Error(
    `Cloudflare default profile preflight failed (${subdomainResponse.status}); authentication method was not changed.`,
  );
const {
  result: { subdomain },
} = (await subdomainResponse.json()) as { result: { subdomain: string } };
const name = app.stage === "production" ? "palisade" : `palisade-${app.stage}`;
const domain = process.env.PALISADE_DOMAIN;
const origin = app.local
  ? "http://localhost:8787"
  : domain
    ? `https://${domain}`
    : `https://${name}.${subdomain}.workers.dev`;
const database = await D1Database("database", {
  name: `${name}-data`,
  migrationsDir: "apps/worker/migrations",
  profile: "default",
});
const deadLetters = await Queue("monitor-dead-letters", {
  name: `${name}-monitor-dead-letters`,
  profile: "default",
});
const monitoring = await Queue<{ userId: string }>("monitoring", {
  name: `${name}-monitor`,
  dlq: deadLetters,
  profile: "default",
});
const assets = await Assets({ path: "apps/web/dist" });
const emailFrom = process.env.PALISADE_EMAIL_FROM;
export const worker = await Worker("web", {
  name,
  entrypoint: "apps/worker/src/index.ts",
  profile: "default",
  compatibility: "node",
  compatibilityDate: "2026-09-01",
  url: true,
  ...(domain ? { domains: [domain] } : {}),
  bindings: {
    DB: database,
    ASSETS: assets,
    AI: Ai(),
    MONITOR_QUEUE: monitoring,
    APP_URL: origin,
    BETTER_AUTH_SECRET: alchemy.secret(secret("BETTER_AUTH_SECRET")),
    DATA_ENCRYPTION_KEY: alchemy.secret(secret("DATA_ENCRYPTION_KEY")),
    ...(emailFrom
      ? {
          EMAIL_FROM: emailFrom,
          EMAIL: EmailSender({ allowedSenderAddresses: [emailFrom] }),
        }
      : {}),
  },
  assets: {
    not_found_handling: "single-page-application",
    run_worker_first: true,
  },
  crons: ["17 8 * * *"],
  eventSources: [
    {
      queue: monitoring,
      settings: {
        batchSize: 5,
        maxConcurrency: 2,
        maxRetries: 3,
        deadLetterQueue: deadLetters,
      },
    },
  ],
  dev: { port: 8787 },
});
console.log(
  JSON.stringify({
    url: origin,
    workerUrl: worker.url,
    database: database.name,
    profile: "default",
    emailConfigured: Boolean(emailFrom),
  }),
);
await app.finalize();
