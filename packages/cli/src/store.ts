import {
  chmod,
  lstat,
  mkdir,
  open,
  readFile,
  rename,
  rm,
} from "node:fs/promises";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { PalisadeError } from "./errors";

export const MAX_STATE_BYTES = 8 * 1024 * 1024;
export function defaultDataDir() {
  return process.env.PALISADE_DATA_DIR || join(homedir(), ".palisade");
}
/** Atomic local JSON writes under a process-safe exclusive directory lock. No credentials are stored here. */
export class LocalStore<T> {
  readonly directory: string;
  readonly path: string;
  constructor(
    directory = defaultDataDir(),
    private validate: (value: unknown) => T,
  ) {
    this.directory = resolve(directory);
    this.path = join(this.directory, "workspace.json");
  }
  private async ensureDirectory() {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    const info = await lstat(this.directory);
    if (!info.isDirectory() || info.isSymbolicLink())
      throw new PalisadeError(
        "UNSAFE_PATH",
        "The data directory must be a real directory, not a symbolic link.",
      );
    await chmod(this.directory, 0o700);
  }
  async read(): Promise<T | null> {
    try {
      const info = await lstat(this.path);
      if (!info.isFile() || info.isSymbolicLink())
        throw new PalisadeError(
          "UNSAFE_PATH",
          "The workspace must be a regular file.",
        );
      if (info.size > MAX_STATE_BYTES)
        throw new PalisadeError(
          "STATE_TOO_LARGE",
          "Workspace exceeds the 8 MiB safety limit.",
        );
      return this.validate(JSON.parse(await readFile(this.path, "utf8")));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
      if (error instanceof PalisadeError) throw error;
      throw new PalisadeError(
        "INVALID_STATE",
        "The workspace could not be read or validated. Your file has been preserved; restore a valid export before continuing.",
      );
    }
  }
  async update(mutate: (current: T | null) => Promise<T> | T): Promise<T> {
    await this.ensureDirectory();
    const lock = join(this.directory, ".write-lock");
    const deadline = Date.now() + 5000;
    for (;;) {
      try {
        await mkdir(lock, { mode: 0o700 });
        break;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        if (Date.now() >= deadline)
          throw new PalisadeError(
            "WORKSPACE_BUSY",
            "Another process is updating this workspace. Retry shortly. If a previous process crashed, remove .write-lock only after confirming no Palisade process is running.",
          );
        await new Promise((resolve) => setTimeout(resolve, 30));
      }
    }
    const temporaryPath = join(
      this.directory,
      `.workspace-${crypto.randomUUID()}.tmp`,
    );
    try {
      const next = this.validate(await mutate(await this.read()));
      const json = JSON.stringify(next, null, 2) + "\n";
      if (Buffer.byteLength(json) > MAX_STATE_BYTES)
        throw new PalisadeError(
          "STATE_TOO_LARGE",
          "Workspace exceeds the 8 MiB safety limit.",
        );
      const file = await open(temporaryPath, "wx", 0o600);
      try {
        await file.writeFile(json, "utf8");
        await file.sync();
      } finally {
        await file.close();
      }
      await rename(temporaryPath, this.path);
      return next;
    } finally {
      await rm(temporaryPath, { force: true });
      await rm(lock, { recursive: true, force: true });
    }
  }
}
