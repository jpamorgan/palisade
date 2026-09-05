import { parseArgs } from "node:util";
import { readFile, open, lstat } from "node:fs/promises";
import { constants } from "node:fs";
import { resolve } from "node:path";
import {
  createService,
  LocalService,
  RemoteService,
  type AuditService,
} from "./service";
import { MAX_STATE_BYTES } from "./store";
import { PalisadeError, errorInfo } from "./errors";
import { renderReport } from "./report";
import type { Workspace, Evaluation, CheckDefinition } from "@palisade/core";

export const HELP = `Palisade · private personal security audits

Usage: palisade <command> [options]

  init --name <name>                     Create a local workspace
  status                                Current posture, coverage, and next gaps
  workspace set [--name <name>] [--region <code>] [--monitoring|--no-monitoring]
  checks [check-id] [--category <id>]     Explore checks and verification guidance
  assets list                           Show assets in scope
  assets add --kind <kind> --label <name> [--value <identifier>] [--critical]
  assets edit <id> [--label <name>] [--value <identifier>] [--recovery <ids>]
  assets remove <id> --confirm           Remove an asset from current scope
  evidence add <check-id> --status <status> --notes <observation> [--asset <id>]
  actions plan|complete <check-id> [--asset <id>] [--notes <notes>]
  audit [--fail-under <0-100>]            Re-evaluate and save a score snapshot
  audit delete <snapshot-id> --confirm   Delete one saved snapshot, retain evidence
  history                               List saved audit snapshots
  scan mac --asset <id> --consent        Read five local Mac security settings
  scan hibp --asset <id> --consent        Send an owned email address to HIBP
  scan footprint --asset <id> --consent  Search a public identifier with Brave
  scan threats                          Refresh public CISA and breach feeds
  integrations                          Check provider availability
  export [--out <file>]                  Export private workspace JSON
  import <file>                         Validate and merge; reverify imported proof
  report --out <file.html>               Write a private standalone HTML checklist
  sync push|pull --host <origin>         Merge local and hosted audit records

Options:
  --data-dir <directory>                 Local state (default: ~/.palisade)
  --host <https://host>                  Use hosted API instead of local state
  --json                                Machine-readable JSON
  --force                               Explicitly replace an existing export file
  --help                                Show this help
  --version                             Show version

Environment: PALISADE_HOST, PALISADE_TOKEN, PALISADE_DATA_DIR, HIBP_API_KEY, BRAVE_SEARCH_API_KEY.
Tokens and provider keys are read from environment only, never saved by the CLI.
Statuses: pass, partial, fail, unknown, not_applicable. Use checks <id> before recording.
Consent confirms you own or are authorized to audit the selected asset and authorize
its stated disclosure. Mac scans never change settings. Audit does not refresh evidence.
Exit codes: 0 success; 1 operation/provider failure; 2 usage or score threshold; 3 auth.
`;
interface Envelope {
  workspace: Workspace;
  evaluation: Evaluation;
  revision: number;
  receipt?: { status: string; message: string };
}
interface Output {
  stdout(text: string): void;
  stderr(text: string): void;
}
const terminalSafe = (text: string) =>
  text.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g, "");
function expectPositionals(args: string[], min: number, max = min) {
  if (args.length < min || args.length > max)
    throw new PalisadeError(
      "USAGE",
      "Invalid command arguments. Run palisade --help.",
      2,
    );
}
async function readImport(path: string) {
  const info = await lstat(path);
  if (!info.isFile() || info.size > MAX_STATE_BYTES)
    throw new PalisadeError(
      "INVALID_IMPORT",
      "Import must be a JSON file no larger than 8 MiB.",
      2,
    );
  try {
    return JSON.parse(await readFile(path, "utf8"));
  } catch {
    throw new PalisadeError(
      "INVALID_IMPORT",
      "The import file is not valid JSON.",
      2,
    );
  }
}
async function writePrivate(path: string, text: string, force: boolean) {
  const absolute = resolve(path);
  // Never follow a destination symlink, including when --force is explicit.
  try {
    const info = await lstat(absolute);
    if (info.isSymbolicLink() || !info.isFile())
      throw new PalisadeError(
        "UNSAFE_PATH",
        "The export destination must be a regular file.",
        2,
      );
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  const file = await open(
    absolute,
    constants.O_WRONLY |
      constants.O_CREAT |
      constants.O_NOFOLLOW |
      (force ? constants.O_TRUNC : constants.O_EXCL),
    0o600,
  ).catch((error) => {
    if (error.code === "EEXIST")
      throw new PalisadeError(
        "FILE_EXISTS",
        "The destination exists. Use a new path or --force to replace it.",
        2,
      );
    throw error;
  });
  try {
    await file.chmod(0o600);
    await file.writeFile(text);
    await file.sync();
  } finally {
    await file.close();
  }
  return absolute;
}
function formatEnvelope(data: Envelope): string {
  const { workspace, evaluation } = data;
  const score =
    evaluation.score === null ? "Unassessed" : `${evaluation.score}/100`;
  const lines = [
    `${workspace.name}`,
    `Security posture: ${score} · ${evaluation.coverage}% assessed`,
    `${workspace.assets.length} assets · ${workspace.evidence.length} evidence records · ${workspace.snapshots.length} audits`,
  ];
  if (data.receipt)
    lines.push(`\n${data.receipt.status}: ${data.receipt.message}`);
  if (evaluation.findings.length)
    lines.push(
      "\nNext checks:",
      ...evaluation.findings
        .slice(0, 5)
        .map((finding) => `  ${finding.checkId}  ${finding.title}`),
    );
  lines.push("\nUse palisade checks <check-id> for verification steps.");
  return lines.join("\n");
}

export async function runCli(
  argv: string[],
  io: Output = {
    stdout: (text) => console.log(text),
    stderr: (text) => console.error(text),
  },
): Promise<number> {
  let json = argv.includes("--json");
  try {
    const { values: flags, positionals } = parseArgs({
      args: argv,
      allowPositionals: true,
      strict: true,
      options: {
        "data-dir": { type: "string" },
        host: { type: "string" },
        json: { type: "boolean" },
        help: { type: "boolean", short: "h" },
        version: { type: "boolean" },
        name: { type: "string" },
        region: { type: "string" },
        monitoring: { type: "boolean" },
        "no-monitoring": { type: "boolean" },
        category: { type: "string" },
        kind: { type: "string" },
        label: { type: "string" },
        value: { type: "string" },
        critical: { type: "boolean" },
        "not-critical": { type: "boolean" },
        recovery: { type: "string" },
        asset: { type: "string" },
        status: { type: "string" },
        notes: { type: "string" },
        "observed-at": { type: "string" },
        consent: { type: "boolean" },
        confirm: { type: "boolean" },
        out: { type: "string" },
        force: { type: "boolean" },
        "fail-under": { type: "string" },
      },
    });
    json = Boolean(flags.json);
    if (flags.version) {
      io.stdout("0.1.0");
      return 0;
    }
    if (flags.help || !positionals.length) {
      io.stdout(HELP);
      return 0;
    }
    const host = flags.host ?? process.env.PALISADE_HOST;
    const dataDir = flags["data-dir"] ?? process.env.PALISADE_DATA_DIR;
    const service = createService({
      host,
      dataDir,
      token: process.env.PALISADE_TOKEN,
    });
    const [command, ...args] = positionals;
    let threshold: number | undefined;
    if (flags["fail-under"] !== undefined) {
      threshold = Number(flags["fail-under"]);
      if (
        command !== "audit" ||
        !Number.isFinite(threshold) ||
        threshold < 0 ||
        threshold > 100 ||
        !flags["fail-under"].trim()
      )
        throw new PalisadeError(
          "USAGE",
          "--fail-under is only valid with audit and must be a number from 0 to 100.",
          2,
        );
    }
    const required = (name: keyof typeof flags): string => {
      const value = flags[name];
      if (typeof value !== "string" || !value.trim())
        throw new PalisadeError(
          "USAGE",
          `--${name} is required. Run palisade --help.`,
          2,
        );
      return value;
    };
    const output = (data: unknown, human?: string) =>
      io.stdout(
        json
          ? JSON.stringify(data, null, 2)
          : terminalSafe(human ?? JSON.stringify(data, null, 2)),
      );
    let result: any;
    if (command === "init") {
      expectPositionals(args, 0);
      if (host)
        throw new PalisadeError(
          "LOCAL_ONLY",
          "Hosted workspaces are created at signup. Use status to access your hosted workspace.",
          2,
        );
      result = await (service as LocalService).init(
        flags.name ?? "My security audit",
      );
    } else if (command === "status") {
      expectPositionals(args, 0);
      result = await service.request("GET", "/workspace");
    } else if (command === "workspace") {
      expectPositionals(args, 1);
      if (args[0] !== "set")
        throw new PalisadeError(
          "USAGE",
          "Use workspace set with --name, --region, --monitoring, or --no-monitoring.",
          2,
        );
      if (flags.monitoring && flags["no-monitoring"])
        throw new PalisadeError(
          "USAGE",
          "Choose either --monitoring or --no-monitoring.",
          2,
        );
      if (
        flags.name === undefined &&
        flags.region === undefined &&
        flags.monitoring === undefined &&
        flags["no-monitoring"] === undefined
      )
        throw new PalisadeError(
          "USAGE",
          "Provide a workspace preference to update.",
          2,
        );
      const current = (await service.request("GET", "/workspace")) as Envelope;
      result = await service.request("PATCH", "/workspace", {
        revision: current.revision,
        ...(flags.name !== undefined ? { name: flags.name } : {}),
        settings: {
          ...(flags.region !== undefined ? { region: flags.region } : {}),
          ...(flags.monitoring !== undefined ||
          flags["no-monitoring"] !== undefined
            ? { monitoring: Boolean(flags.monitoring) }
            : {}),
        },
      });
    } else if (command === "checks") {
      expectPositionals(args, 0, 1);
      const catalog = (await service.request("GET", "/catalog")) as {
        checks: CheckDefinition[];
      };
      const checks = catalog.checks.filter(
        (check) =>
          (!args[0] || check.id === args[0]) &&
          (!flags.category || check.categoryId === flags.category),
      );
      if (!checks.length)
        throw new PalisadeError(
          "NOT_FOUND",
          "No checks match that ID or category.",
          2,
        );
      const human = args[0]
        ? checks
            .map(
              (check) =>
                `${check.title} (${check.id})\n${check.description}\n\nVerify:\n${check.guidance.map((step, index) => `  ${index + 1}. ${step}`).join("\n")}\n\nEvidence required: ${check.verification}\n\nMitigation: ${check.remediation.title}\n${check.remediation.steps.map((step, index) => `  ${index + 1}. ${step}`).join("\n")}\n\nFreshness: ${check.freshnessDays} days · Severity: ${check.severity}${check.remediation.lockoutRisk ? "\nCheck recovery access first: this mitigation can lock you out." : ""}`,
            )
            .join("\n\n")
        : checks
            .map((check) => `${check.id.padEnd(36)} ${check.title}`)
            .join("\n");
      output({ ...catalog, checks }, human);
      return 0;
    } else if (command === "assets") {
      if (args[0] === "list") {
        expectPositionals(args, 1);
        const data = (await service.request("GET", "/workspace")) as Envelope;
        output(
          { assets: data.workspace.assets },
          data.workspace.assets.length
            ? data.workspace.assets
                .map(
                  (asset) =>
                    `${asset.id}  ${asset.kind}  ${asset.label}${asset.critical ? " [critical]" : ""}`,
                )
                .join("\n")
            : 'No assets yet. Add one with palisade assets add --kind email --label "Primary email".',
        );
        return 0;
      }
      if (args[0] === "add") {
        expectPositionals(args, 1);
        result = await service.request("POST", "/assets", {
          kind: required("kind"),
          label: required("label"),
          ...(flags.value ? { value: flags.value } : {}),
          critical: Boolean(flags.critical),
        });
      } else if (args[0] === "edit") {
        expectPositionals(args, 2);
        if (flags.critical && flags["not-critical"])
          throw new PalisadeError(
            "USAGE",
            "Choose either --critical or --not-critical.",
            2,
          );
        const patch = {
          ...(flags.label !== undefined ? { label: flags.label } : {}),
          ...(flags.value !== undefined ? { value: flags.value } : {}),
          ...(flags.critical !== undefined ||
          flags["not-critical"] !== undefined
            ? { critical: Boolean(flags.critical) }
            : {}),
          ...(flags.recovery !== undefined
            ? {
                recoveryAssetIds: flags.recovery
                  ? flags.recovery.split(",").map((id) => id.trim())
                  : [],
              }
            : {}),
        };
        if (!Object.keys(patch).length)
          throw new PalisadeError(
            "USAGE",
            "Provide --label, --value, --critical, --not-critical, or --recovery to edit.",
            2,
          );
        result = await service.request(
          "PATCH",
          "/assets/" + encodeURIComponent(args[1]!),
          patch,
        );
      } else if (args[0] === "remove") {
        expectPositionals(args, 2);
        if (!flags.confirm)
          throw new PalisadeError(
            "CONFIRM_REQUIRED",
            "Asset removal changes audit scope. Add --confirm to remove the selected asset; historical snapshots remain.",
            2,
          );
        result = await service.request(
          "DELETE",
          "/assets/" + encodeURIComponent(args[1]!),
        );
      } else
        throw new PalisadeError(
          "USAGE",
          "Use assets list, assets add, assets edit, or assets remove. Run palisade --help.",
          2,
        );
    } else if (command === "evidence") {
      expectPositionals(args, 2);
      if (args[0] !== "add")
        throw new PalisadeError("USAGE", "Use evidence add <check-id>.", 2);
      result = await service.request("POST", "/evidence", {
        checkId: args[1],
        status: required("status"),
        notes: required("notes"),
        ...(flags.asset ? { assetId: flags.asset } : {}),
        ...(flags["observed-at"] ? { observedAt: flags["observed-at"] } : {}),
      });
    } else if (command === "actions") {
      expectPositionals(args, 2);
      if (!["plan", "complete"].includes(args[0]!))
        throw new PalisadeError(
          "USAGE",
          "Use actions plan or actions complete <check-id>.",
          2,
        );
      result = await service.request("POST", "/actions", {
        checkId: args[1],
        status: args[0] === "plan" ? "planned" : "completed",
        ...(flags.asset ? { assetId: flags.asset } : {}),
        ...(flags.notes ? { notes: flags.notes } : {}),
      });
    } else if (command === "audit") {
      if (args[0] === "delete") {
        expectPositionals(args, 2);
        if (!flags.confirm)
          throw new PalisadeError(
            "CONFIRM_REQUIRED",
            "Snapshot deletion is permanent. Export it first if needed, then add --confirm to delete only this snapshot.",
            2,
          );
        if (threshold !== undefined)
          throw new PalisadeError(
            "USAGE",
            "--fail-under applies only to creating an audit.",
            2,
          );
        result = await service.request(
          "DELETE",
          "/audits/" + encodeURIComponent(args[1]!),
          { confirmation: "DELETE" },
        );
      } else {
        expectPositionals(args, 0);
        result = await service.request("POST", "/audits", {});
      }
    } else if (command === "history") {
      expectPositionals(args, 0);
      const data = (await service.request("GET", "/workspace")) as Envelope;
      output(
        { snapshots: data.workspace.snapshots },
        data.workspace.snapshots.length
          ? data.workspace.snapshots
              .map(
                (snapshot) =>
                  `${snapshot.createdAt}  ${snapshot.evaluation.score ?? "—"}/100  ${snapshot.evaluation.coverage}% assessed  ${snapshot.id}`,
              )
              .join("\n")
          : "No saved audits yet. Run palisade audit.",
      );
      return 0;
    } else if (command === "integrations") {
      expectPositionals(args, 0);
      output(await service.request("GET", "/integrations"));
      return 0;
    } else if (command === "scan") {
      expectPositionals(args, 1);
      if (!["mac", "hibp", "footprint", "threats"].includes(args[0]!))
        throw new PalisadeError(
          "USAGE",
          "Use scan mac, scan hibp, scan footprint, or scan threats.",
          2,
        );
      if (args[0] === "mac" && host)
        throw new PalisadeError(
          "LOCAL_ONLY",
          "Run the Mac collector in local mode, then explicitly sync the results to your hosted audit.",
          2,
        );
      if (args[0] !== "threats" && !flags.consent)
        throw new PalisadeError(
          "CONSENT_REQUIRED",
          "Add --consent after authorizing this audit of your own asset. HIBP sends the email to Have I Been Pwned; footprint sends the asset identifier to Brave; Mac reads local security settings.",
          2,
        );
      result = await service.request(
        "POST",
        "/scans/" + args[0],
        args[0] === "threats"
          ? {}
          : { assetId: required("asset"), consent: true },
      );
    } else if (command === "export") {
      expectPositionals(args, 0);
      const data = await service.request("GET", "/export");
      if (flags.out) {
        const path = await writePrivate(
          flags.out,
          JSON.stringify(data, null, 2) + "\n",
          Boolean(flags.force),
        );
        output(
          { path },
          `Export saved to ${path}. It contains private audit data.`,
        );
      } else io.stdout(JSON.stringify(data, null, 2));
      return 0;
    } else if (command === "import") {
      expectPositionals(args, 1);
      result = await service.request("POST", "/imports", {
        workspace: await readImport(args[0]!),
      });
    } else if (command === "report") {
      expectPositionals(args, 0);
      const data = (await service.request("GET", "/workspace")) as Envelope;
      const path = await writePrivate(
        required("out"),
        renderReport(data.workspace, data.evaluation),
        Boolean(flags.force),
      );
      output(
        { path },
        `Private report saved to ${path}. Open it in a browser.`,
      );
      return 0;
    } else if (command === "sync") {
      expectPositionals(args, 1);
      if (!host)
        throw new PalisadeError(
          "HOST_REQUIRED",
          "Specify --host or PALISADE_HOST for sync.",
          2,
        );
      if (!["push", "pull"].includes(args[0]!))
        throw new PalisadeError("USAGE", "Use sync push or sync pull.", 2);
      const local = new LocalService(dataDir);
      const remote = new RemoteService(host, process.env.PALISADE_TOKEN);
      const source: AuditService = args[0] === "push" ? local : remote;
      const destination: AuditService = args[0] === "push" ? remote : local;
      result = await destination.request("POST", "/imports", {
        workspace: await source.request("GET", "/export"),
      });
    } else
      throw new PalisadeError(
        "USAGE",
        `Unknown command: ${command}. Run palisade --help.`,
        2,
      );
    output(
      result,
      result?.workspace && result?.evaluation
        ? formatEnvelope(result)
        : undefined,
    );
    if (
      result?.receipt &&
      ["error", "unavailable"].includes(result.receipt.status)
    )
      return 1;
    if (
      threshold !== undefined &&
      (result.evaluation.score === null || result.evaluation.score < threshold)
    )
      return 2;
    return 0;
  } catch (error) {
    const info = errorInfo(error);
    io.stderr(
      json
        ? JSON.stringify({ error: info })
        : `Palisade: ${terminalSafe(info.message)}`,
    );
    return error instanceof PalisadeError
      ? error.exitCode
      : error instanceof Error &&
          (error.name === "ZodError" ||
            ("code" in error &&
              String(error.code).startsWith("ERR_PARSE_ARGS")))
        ? 2
        : 1;
  }
}
