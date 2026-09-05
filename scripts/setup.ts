import { mkdir, readFile, writeFile, chmod } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

const directory = join(homedir(), ".config", "palisade");
await mkdir(directory, { recursive: true, mode: 0o700 });
const path = join(directory, "deployment.json");
let secrets: Record<string, string>;
try {
  secrets = JSON.parse(await readFile(path, "utf8"));
} catch (error) {
  if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  const random = () =>
    Buffer.from(crypto.getRandomValues(new Uint8Array(48))).toString(
      "base64url",
    );
  secrets = {
    BETTER_AUTH_SECRET: random(),
    DATA_ENCRYPTION_KEY: random(),
    ALCHEMY_PASSWORD: random(),
  };
  await writeFile(path, JSON.stringify(secrets), { mode: 0o600, flag: "wx" });
}
await chmod(path, 0o600);
await writeFile(
  ".dev.vars",
  `BETTER_AUTH_SECRET=${secrets.BETTER_AUTH_SECRET}\nDATA_ENCRYPTION_KEY=${secrets.DATA_ENCRYPTION_KEY}\n`,
  { mode: 0o600 },
);
await chmod(".dev.vars", 0o600);
console.log(
  "Application secrets are ready in the local Palisade configuration directory. No Cloudflare credentials were copied or changed.",
);
