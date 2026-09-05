import { execFile } from "node:child_process";
import type { EvidenceStatus } from "@palisade/core";

export type CommandId =
  "filevault" | "firewall" | "gatekeeper" | "sip" | "updates";
export const MAC_COMMANDS = {
  filevault: { executable: "/usr/bin/fdesetup", args: ["status"] },
  firewall: {
    executable: "/usr/libexec/ApplicationFirewall/socketfilterfw",
    args: ["--getglobalstate"],
  },
  gatekeeper: { executable: "/usr/sbin/spctl", args: ["--status"] },
  sip: { executable: "/usr/bin/csrutil", args: ["status"] },
  updates: {
    executable: "/usr/bin/defaults",
    args: [
      "read",
      "/Library/Preferences/com.apple.SoftwareUpdate",
      "AutomaticCheckEnabled",
    ],
  },
} as const;
export interface CommandResult {
  code: number;
  stdout: string;
}
export type CommandRunner = (id: CommandId) => Promise<CommandResult>;
export interface LocalObservation {
  collector: CommandId;
  status: EvidenceStatus;
  summary: string;
  checkId?: string;
  facts: Record<string, string | boolean | number>;
}
/** Only fixed read-only commands can reach execFile; no arbitrary paths, command text, or shell interpolation. */
export const runMacCommand: CommandRunner = async (id) => {
  const command = MAC_COMMANDS[id];
  return new Promise((resolve) =>
    execFile(
      command.executable,
      [...command.args],
      {
        timeout: 8000,
        maxBuffer: 16_384,
        encoding: "utf8",
        env: {
          PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
          LANG: "en_US.UTF-8",
          LC_ALL: "en_US.UTF-8",
        },
      },
      (error, stdout) => {
        resolve({
          code: error ? (typeof error.code === "number" ? error.code : 1) : 0,
          stdout: String(stdout),
        });
      },
    ),
  );
};
export function parseMacObservation(
  id: CommandId,
  result: CommandResult,
): LocalObservation {
  // Never persist raw stdout: some system versions include user/device-identifying information.
  const base = { collector: id, facts: { collector: id, platform: "darwin" } };
  if (result.code !== 0)
    return {
      ...base,
      status: "unknown",
      summary: "The setting could not be read with current permissions.",
    };
  const tests: Record<
    CommandId,
    { pass: RegExp; fail: RegExp; label: string }
  > = {
    filevault: {
      pass: /^FileVault is On\.\s*$/i,
      fail: /^FileVault is Off\.\s*$/i,
      label: "FileVault disk encryption",
    },
    firewall: {
      pass: /Firewall is enabled\. \(State = 1\)/i,
      fail: /Firewall is disabled\. \(State = 0\)/i,
      label: "Application firewall",
    },
    gatekeeper: {
      pass: /^assessments enabled\s*$/i,
      fail: /^assessments disabled\s*$/i,
      label: "Gatekeeper app assessment",
    },
    sip: {
      pass: /^System Integrity Protection status: enabled\.\s*$/i,
      fail: /^System Integrity Protection status: disabled\.\s*$/i,
      label: "System Integrity Protection",
    },
    updates: {
      pass: /^1\s*$/,
      fail: /^0\s*$/,
      label: "Automatic update checking",
    },
  };
  const test = tests[id];
  const status = test.pass.test(result.stdout.trim())
    ? "pass"
    : test.fail.test(result.stdout.trim())
      ? "fail"
      : "unknown";
  return {
    ...base,
    status,
    summary:
      status === "unknown"
        ? `${test.label}: unrecognized response; verify manually.`
        : `${test.label} is ${status === "pass" ? "enabled" : "disabled"}.`,
    facts: {
      ...base.facts,
      ...(status === "unknown" ? {} : { enabled: status === "pass" }),
    },
  };
}
export async function collectMac(
  options: { platform?: string; runner?: CommandRunner } = {},
) {
  if ((options.platform ?? process.platform) !== "darwin")
    return {
      status: "unavailable" as const,
      message:
        "The Mac collector is available only on macOS. Use guided device checks on this platform.",
      observations: [] as LocalObservation[],
    };
  const runner = options.runner ?? runMacCommand;
  const observations = await Promise.all(
    (Object.keys(MAC_COMMANDS) as CommandId[]).map(async (id) => {
      try {
        return parseMacObservation(id, await runner(id));
      } catch {
        return parseMacObservation(id, { code: 1, stdout: "" });
      }
    }),
  );
  return {
    status: observations.some((o) => o.status === "unknown")
      ? ("partial" as const)
      : ("complete" as const),
    message:
      "Read five macOS settings. No account settings, credentials, browser data, or private files were accessed.",
    observations,
  };
}
