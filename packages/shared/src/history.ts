import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import type { DatabaseSync as DatabaseSyncType } from "node:sqlite";
import { getHomeDir, ensureHomeDir } from "./paths.js";
import { getOrCreateKey, encryptPayload, decryptPayload } from "./secure-store.js";
import { loadConfig, HistoryRetention } from "./config.js";

export interface OtpHistoryEntry {
  id?: number;
  sender: string;
  senderDomain: string | null;
  alias: string;
  code: string;
  receivedAt: number;
}

export interface AddHistoryEntryOptions {
  sender: string;
  senderDomain?: string | null;
  alias: string;
  code: string;
  receivedAt?: number;
}

export interface HistoryStoreOptions {
  homeDir?: string;
  retention?: HistoryRetention;
  sqliteLoader?: () => any;
}

type SqliteModule = {
  DatabaseSync: new (path: string, options?: any) => DatabaseSyncType;
};

let cachedSqliteModule: SqliteModule | undefined;

/**
 * Ensures node:sqlite is supported in the current Node runtime.
 * Throws a clear error if node:sqlite cannot be imported.
 */
export function ensureSqliteSupported(loader?: () => any): SqliteModule {
  if (loader) {
    try {
      const res = loader();
      if (!res?.DatabaseSync) {
        throw new Error("Node 22.13 or newer is required");
      }
      return res;
    } catch {
      throw new Error("Node 22.13 or newer is required");
    }
  }

  if (cachedSqliteModule) {
    return cachedSqliteModule;
  }

  try {
    const require = createRequire(import.meta.url);
    const mod = require("node:sqlite");
    if (!mod?.DatabaseSync) {
      throw new Error("Node 22.13 or newer is required");
    }
    cachedSqliteModule = mod;
    return mod;
  } catch {
    throw new Error("Node 22.13 or newer is required");
  }
}

export class HistoryStore {
  public readonly homeDir: string;
  private readonly retentionOverride?: HistoryRetention;
  private readonly sqliteLoader?: () => any;
  private db: DatabaseSyncType | null = null;

  constructor(homeDirOrOptions?: string | HistoryStoreOptions) {
    if (typeof homeDirOrOptions === "string") {
      this.homeDir = homeDirOrOptions;
    } else if (typeof homeDirOrOptions === "object" && homeDirOrOptions !== null) {
      this.homeDir = homeDirOrOptions.homeDir ?? getHomeDir();
      this.retentionOverride = homeDirOrOptions.retention;
      this.sqliteLoader = homeDirOrOptions.sqliteLoader;
    } else {
      this.homeDir = getHomeDir();
    }

    this.initDb();
  }

  private initDb(): void {
    ensureHomeDir(this.homeDir);
    const dbPath = path.join(this.homeDir, "history.db");

    const sqlite = ensureSqliteSupported(this.sqliteLoader);
    const db = new sqlite.DatabaseSync(dbPath);

    db.exec("PRAGMA secure_delete = ON;");
    db.exec("PRAGMA journal_mode = DELETE;");

    if (process.platform !== "win32") {
      try {
        fs.chmodSync(dbPath, 0o600);
      } catch {
        // ignore chmod errors on unsupported filesystems
      }
    }

    db.exec(
      "CREATE TABLE IF NOT EXISTS otp_history (" +
        "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
        "sender TEXT, " +
        "sender_domain TEXT, " +
        "alias TEXT, " +
        "code_enc TEXT, " +
        "received_at INTEGER" +
        ");"
    );

    this.db = db;
  }

  private getDb(): DatabaseSyncType {
    if (!this.db) {
      this.initDb();
    }
    return this.db!;
  }

  /**
   * Returns current retention, checking constructor override first, then config.json.
   */
  public getRetention(): HistoryRetention {
    if (this.retentionOverride) {
      return this.retentionOverride;
    }
    try {
      const config = loadConfig(this.homeDir);
      return config.historyRetention ?? "5m";
    } catch {
      return "5m";
    }
  }

  /**
   * Adds an OTP to history.
   * If retention is "off", stores nothing.
   */
  public add(entry: AddHistoryEntryOptions): void {
    const retention = this.getRetention();
    if (retention === "off") {
      return;
    }

    const key = getOrCreateKey(this.homeDir);
    const codeEnc = encryptPayload(entry.code, key);
    const receivedAt = entry.receivedAt ?? Date.now();

    const db = this.getDb();
    const stmt = db.prepare(
      "INSERT INTO otp_history (sender, sender_domain, alias, code_enc, received_at) VALUES (?, ?, ?, ?, ?);"
    );
    stmt.run(
      entry.sender,
      entry.senderDomain ?? null,
      entry.alias,
      codeEnc,
      receivedAt
    );
  }

  /**
   * Lists history entries, newest first, with code decrypted.
   */
  public list(): OtpHistoryEntry[] {
    const db = this.getDb();
    const stmt = db.prepare(
      "SELECT id, sender, sender_domain, alias, code_enc, received_at FROM otp_history ORDER BY received_at DESC, id DESC;"
    );
    const rows = stmt.all() as Array<{
      id: number;
      sender: string;
      sender_domain: string | null;
      alias: string;
      code_enc: string;
      received_at: number;
    }>;

    const key = getOrCreateKey(this.homeDir);
    const result: OtpHistoryEntry[] = [];

    for (const row of rows) {
      try {
        const code = decryptPayload(row.code_enc, key);
        result.push({
          id: row.id,
          sender: row.sender,
          senderDomain: row.sender_domain,
          alias: row.alias,
          code,
          receivedAt: Number(row.received_at)
        });
      } catch {
        // Skip rows that fail decryption
      }
    }

    return result;
  }

  /**
   * Removes rows older than the retention threshold.
   * If retention is "off", deletes all rows.
   */
  public purge(now: number = Date.now()): number {
    const retention = this.getRetention();
    const db = this.getDb();

    if (retention === "off") {
      const res = db.prepare("DELETE FROM otp_history;").run();
      return Number(res.changes);
    }

    let maxAgeMs: number;
    switch (retention) {
      case "5m":
        maxAgeMs = 5 * 60 * 1000;
        break;
      case "30m":
        maxAgeMs = 30 * 60 * 1000;
        break;
      case "1h":
        maxAgeMs = 60 * 60 * 1000;
        break;
      default:
        maxAgeMs = 5 * 60 * 1000;
        break;
    }

    const cutoff = now - maxAgeMs;
    const res = db.prepare("DELETE FROM otp_history WHERE received_at < ?;").run(cutoff);
    return Number(res.changes);
  }

  /**
   * Deletes all rows and runs VACUUM.
   */
  public clear(): number {
    const db = this.getDb();
    const res = db.prepare("DELETE FROM otp_history;").run();
    db.exec("VACUUM;");
    return Number(res.changes);
  }

  /**
   * Closes the database connection.
   */
  public close(): void {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
  }
}
