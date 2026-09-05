import { expect, test } from "bun:test";
import {
  collectMac,
  parseMacObservation,
  MAC_COMMANDS,
} from "../src/collector";
test("collector is unavailable on other platforms without executing commands", async () => {
  let called = false;
  const result = await collectMac({
    platform: "linux",
    runner: async () => {
      called = true;
      throw new Error("must not execute");
    },
  });
  expect(result.status).toBe("unavailable");
  expect(called).toBe(false);
});
test("failed, transitional, and unexpected settings never receive passing evidence", () => {
  expect(
    parseMacObservation("filevault", { code: 1, stdout: "FileVault is On." })
      .status,
  ).toBe("unknown");
  expect(
    parseMacObservation("filevault", {
      code: 0,
      stdout: "Encryption in progress: 20%",
    }).status,
  ).toBe("unknown");
  expect(
    parseMacObservation("sip", {
      code: 0,
      stdout:
        "System Integrity Protection status: unknown (Custom Configuration).",
    }).status,
  ).toBe("unknown");
  expect(
    parseMacObservation("filevault", { code: 0, stdout: "FileVault is On." })
      .status,
  ).toBe("pass");
  expect(
    parseMacObservation("firewall", {
      code: 0,
      stdout: "Firewall is disabled. (State = 0)",
    }).status,
  ).toBe("fail");
});
test("collector uses only bounded fixed read-only commands and omits raw output", async () => {
  const ids: string[] = [];
  const result = await collectMac({
    platform: "darwin",
    runner: async (id) => {
      ids.push(id);
      return { code: 0, stdout: "sensitive-user-name not a setting" };
    },
  });
  expect(ids.sort()).toEqual(Object.keys(MAC_COMMANDS).sort());
  expect(result.status).toBe("partial");
  expect(result.observations.every((o) => o.status === "unknown")).toBe(true);
  expect(JSON.stringify(result)).not.toContain("sensitive-user-name");
});
