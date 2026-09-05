import { afterEach, expect, test } from "bun:test";
import {
  mkdtemp,
  rm,
  stat,
  writeFile,
  readFile,
  symlink,
} from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { LocalStore } from "../src/store";
const directories: string[] = [];
async function fixture() {
  const dir = await mkdtemp(join(tmpdir(), "palisade-store-"));
  directories.push(dir);
  return {
    dir,
    store: new LocalStore(dir, (value) => {
      if (
        !value ||
        typeof value !== "object" ||
        typeof (value as any).count !== "number"
      )
        throw new Error("Invalid");
      return value as { count: number };
    }),
  };
}
afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((dir) => rm(dir, { recursive: true, force: true })),
  );
});
test("concurrent updates preserve every write and use private filesystem modes", async () => {
  const { store, dir } = await fixture();
  await Promise.all(
    Array.from({ length: 12 }, () =>
      store.update((value) => ({ count: (value?.count ?? 0) + 1 })),
    ),
  );
  expect((await store.read())?.count).toBe(12);
  expect((await stat(dir)).mode & 0o777).toBe(0o700);
  expect((await stat(store.path)).mode & 0o777).toBe(0o600);
});
test("invalid state is preserved and a rejected mutation releases the lock", async () => {
  const { store } = await fixture();
  await store.update(() => ({ count: 3 }));
  await expect(
    store.update(() => {
      throw new Error("No");
    }),
  ).rejects.toThrow("No");
  expect((await store.update(() => ({ count: 4 }))).count).toBe(4);
  await writeFile(store.path, "broken json");
  await expect(store.update(() => ({ count: 0 }))).rejects.toThrow("preserved");
  expect(await readFile(store.path, "utf8")).toBe("broken json");
});
test("workspace symlinks cannot redirect writes", async () => {
  const { store, dir } = await fixture();
  const other = join(dir, "other.json");
  await writeFile(other, '{"count":7}');
  await symlink(other, store.path);
  await expect(store.update(() => ({ count: 0 }))).rejects.toThrow(
    "regular file",
  );
  expect(await readFile(other, "utf8")).toBe('{"count":7}');
});
