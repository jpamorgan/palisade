import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createHash } from "node:crypto";

// Package only the two explicit public entry points, never deployment state.
const entries = [
  ["packages/cli/dist/index.js", "palisade.js"],
  ["packages/mcp/dist/index.js", "palisade-mcp.js"],
] as const;
const bundles = await Promise.all(
  entries.map(async ([path, name]) => ({
    name,
    text: await readFile(path, "utf8"),
  })),
);
const roots = new Set<string>();
for (const bundle of bundles) {
  for (const match of bundle.text.matchAll(
    /node_modules\/\.bun\/[^/\n]+\/node_modules\/(?:@[^/\n]+\/)?[^/\n]+/g,
  ))
    roots.add(match[0]);
}
const notices: string[] = [];
for (const root of [...roots].sort()) {
  const metadata = JSON.parse(
    await readFile(join(root, "package.json"), "utf8"),
  );
  let license: string | undefined;
  for (const name of [
    "LICENSE",
    "LICENSE.md",
    "LICENSE.txt",
    "license",
    "license.md",
    "LICENCE",
    "LICENSE-MIT",
  ]) {
    try {
      license = await readFile(join(root, name), "utf8");
      break;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }
  if (!license)
    throw new Error(
      `Review the license for bundled dependency ${metadata.name}; no license file found.`,
    );
  notices.push(`${metadata.name} ${metadata.version}\n\n${license}`);
}
const directory = "dist/release";
await mkdir(directory, { recursive: true });
const projectLicense = await readFile("LICENSE", "utf8");
const notice = notices.join("\n\n----------------------------------------\n\n");
const comment = `${projectLicense}\n\nBundled dependency notices\n\n${notice}`
  .split("\n")
  .map((line) => `// ${line}`)
  .join("\n");
for (const bundle of bundles) {
  const body = bundle.text.replace(/^#![^\n]*\n/, "");
  await writeFile(
    join(directory, bundle.name),
    `#!/usr/bin/env bun\n${comment}\n${body}`,
    { mode: 0o755 },
  );
}
await writeFile(join(directory, "LICENSE.txt"), projectLicense);
await writeFile(join(directory, "THIRD-PARTY-NOTICES.txt"), notice);
const sums: string[] = [];
for (const name of [
  ...bundles.map((b) => b.name),
  "LICENSE.txt",
  "THIRD-PARTY-NOTICES.txt",
]) {
  const digest = createHash("sha256")
    .update(await readFile(join(directory, name)))
    .digest("hex");
  sums.push(`${digest}  ${name}`);
}
await writeFile(join(directory, "SHA256SUMS"), `${sums.join("\n")}\n`);
console.log(
  `Packaged CLI + MCP with ${roots.size} dependency notices and SHA-256 checksums in ${directory}.`,
);
