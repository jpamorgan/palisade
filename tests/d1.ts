import { Database } from "bun:sqlite";
import { readFileSync, readdirSync } from "node:fs";

/** Test adapter runs real SQLite SQL; deployed smoke tests additionally exercise Cloudflare D1. */
export function testDatabase() {
  const db = new Database(":memory:");
  const migrations = new URL("../apps/worker/migrations/", import.meta.url);
  for (const file of readdirSync(migrations)
    .filter((name) => name.endsWith(".sql"))
    .sort())
    db.exec(readFileSync(new URL(file, migrations), "utf8"));
  class Statement {
    constructor(
      private sql: string,
      private params: unknown[] = [],
    ) {}
    bind(...values: unknown[]) {
      return new Statement(this.sql, values);
    }
    async first(column?: string) {
      const row = db.query(this.sql).get(...(this.params as never[])) as Record<
        string,
        unknown
      > | null;
      return column ? (row?.[column] ?? null) : row;
    }
    async all() {
      const rows = db.query(this.sql).all(...(this.params as never[]));
      return {
        success: true,
        results: rows,
        meta: {
          changes: db.query("SELECT changes() AS n").get()
            ? (db.query("SELECT changes() AS n").get() as { n: number }).n
            : 0,
        },
      };
    }
    async run() {
      const result = db.query(this.sql).run(...(this.params as never[]));
      return {
        success: true,
        results: [],
        meta: {
          changes: result.changes,
          last_row_id: Number(result.lastInsertRowid),
        },
      };
    }
    async raw() {
      return db.query(this.sql).values(...(this.params as never[]));
    }
  }
  return {
    db,
    binding: {
      prepare: (sql: string) => new Statement(sql),
      batch: async (statements: Statement[]) => {
        db.exec("BEGIN");
        try {
          const results = [];
          for (const s of statements) results.push(await s.all());
          db.exec("COMMIT");
          return results;
        } catch (error) {
          db.exec("ROLLBACK");
          throw error;
        }
      },
      exec: async (sql: string) => {
        db.exec(sql);
        return { count: 1, duration: 0 };
      },
    } as unknown as D1Database,
  };
}
