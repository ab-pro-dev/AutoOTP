import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  VERSION,
  TokenStore,
  getOrCreateKey,
  ensureHomeDir,
  StoredTokens,
  getOrCreatePairToken,
  rotatePairToken,
  loadConfig,
  saveConfig,
  validateConfig,
  DEFAULT_CONFIG,
  HistoryStore,
  ensureSqliteSupported
} from "./index.js";

describe("VERSION", () => {
  it("matches semver pattern", () => {
    expect(VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });
});

describe("Encrypted Local Storage (TokenStore)", () => {
  let tempDir: string;
  const originalHome = process.env.AUTOOTP_HOME;

  beforeEach(() => {
    const tmpBase = process.env.TMPDIR || process.env.TEMP || "/tmp";
    tempDir = fs.mkdtempSync(path.join(tmpBase, "autootp-test-"));
    process.env.AUTOOTP_HOME = tempDir;
  });

  afterEach(() => {
    if (originalHome !== undefined) {
      process.env.AUTOOTP_HOME = originalHome;
    } else {
      delete process.env.AUTOOTP_HOME;
    }
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("performs set and get round trip", async () => {
    const store = new TokenStore();
    const tokens: StoredTokens = {
      refreshToken: "refresh-token-123",
      email: "test@example.com",
      addedAt: 1700000000
    };

    await store.set("personal", tokens);
    const retrieved = await store.get("personal");
    expect(retrieved).toEqual(tokens);

    const missing = await store.get("nonexistent");
    expect(missing).toBeNull();
  });

  it("lists accounts and removes an account", async () => {
    const store = new TokenStore();
    await store.set("acc1", { refreshToken: "r1", email: "a1@test.com", addedAt: 1 });
    await store.set("acc2", { refreshToken: "r2", email: "a2@test.com", addedAt: 2 });

    const list = await store.list();
    expect(list.sort()).toEqual(["acc1", "acc2"]);

    const removed = await store.remove("acc1");
    expect(removed).toBe(true);

    expect(await store.list()).toEqual(["acc2"]);
    expect(await store.get("acc1")).toBeNull();

    const removeAgain = await store.remove("acc1");
    expect(removeAgain).toBe(false);
  });

  it("produces different ciphertext on two writes of the same data due to fresh IV", async () => {
    const store = new TokenStore();
    const tokens: StoredTokens = {
      refreshToken: "token-abc",
      email: "abc@example.com",
      addedAt: 12345
    };

    await store.set("acc", tokens);
    const encPath = path.join(tempDir, "tokens.enc");
    const raw1 = JSON.parse(fs.readFileSync(encPath, "utf8"));

    await store.set("acc", tokens);
    const raw2 = JSON.parse(fs.readFileSync(encPath, "utf8"));

    expect(raw1.iv).not.toBe(raw2.iv);
    expect(raw1.data).not.toBe(raw2.data);
    expect(raw1.tag).not.toBe(raw2.tag);
  });

  it("throws 'Token store could not be decrypted' when a byte is flipped in tokens.enc", async () => {
    const store = new TokenStore();
    await store.set("acc", { refreshToken: "token", email: "test@example.com", addedAt: 1 });

    const encPath = path.join(tempDir, "tokens.enc");
    const payload = JSON.parse(fs.readFileSync(encPath, "utf8"));

    const dataBuf = Buffer.from(payload.data, "base64");
    dataBuf[0] ^= 0xff;
    payload.data = dataBuf.toString("base64");
    fs.writeFileSync(encPath, JSON.stringify(payload));

    await expect(store.get("acc")).rejects.toThrow("Token store could not be decrypted");
  });

  it("throws 'Token store could not be decrypted' when key file is replaced", async () => {
    const store = new TokenStore();
    await store.set("acc", { refreshToken: "token", email: "test@example.com", addedAt: 1 });

    const keyPath = path.join(tempDir, "key");
    fs.writeFileSync(keyPath, crypto.randomBytes(32));

    const store2 = new TokenStore();
    await expect(store2.get("acc")).rejects.toThrow("Token store could not be decrypted");
  });

  it("throws when key file is not exactly 32 bytes", async () => {
    ensureHomeDir(tempDir);
    const keyPath = path.join(tempDir, "key");
    fs.writeFileSync(keyPath, crypto.randomBytes(16));

    const store = new TokenStore();
    await expect(store.get("acc")).rejects.toThrow("Key file must be exactly 32 bytes");
    await expect(
      store.set("acc", { refreshToken: "t", email: "e@t.com", addedAt: 1 })
    ).rejects.toThrow("Key file must be exactly 32 bytes");
  });

  it("does not change an existing key on second ensure/key load", () => {
    const key1 = getOrCreateKey(tempDir);
    const keyPath = path.join(tempDir, "key");
    const fileBytes1 = fs.readFileSync(keyPath);

    const key2 = getOrCreateKey(tempDir);
    const fileBytes2 = fs.readFileSync(keyPath);

    expect(key1.equals(key2)).toBe(true);
    expect(fileBytes1.equals(fileBytes2)).toBe(true);
  });

  it("sets mode 700 for home dir and 600 for key and tokens.enc on non-Windows platforms", async () => {
    if (process.platform === "win32") {
      return;
    }

    const store = new TokenStore();
    await store.set("acc", { refreshToken: "t", email: "test@example.com", addedAt: 1 });

    const homeStat = fs.statSync(tempDir);
    expect((homeStat.mode & 0o777).toString(8)).toBe("700");

    const logsStat = fs.statSync(path.join(tempDir, "logs"));
    expect((logsStat.mode & 0o777).toString(8)).toBe("700");

    const keyStat = fs.statSync(path.join(tempDir, "key"));
    expect((keyStat.mode & 0o777).toString(8)).toBe("600");

    const tokensStat = fs.statSync(path.join(tempDir, "tokens.enc"));
    expect((tokensStat.mode & 0o777).toString(8)).toBe("600");
  });
});

describe("Pairing Token (pair.token)", () => {
  let tempDir: string;
  const originalHome = process.env.AUTOOTP_HOME;

  beforeEach(() => {
    const tmpBase = process.env.TMPDIR || process.env.TEMP || "/tmp";
    tempDir = fs.mkdtempSync(path.join(tmpBase, "autootp-pair-test-"));
    process.env.AUTOOTP_HOME = tempDir;
  });

  afterEach(() => {
    if (originalHome !== undefined) {
      process.env.AUTOOTP_HOME = originalHome;
    } else {
      delete process.env.AUTOOTP_HOME;
    }
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("is stable across multiple calls and does not regenerate", () => {
    const token1 = getOrCreatePairToken(tempDir);
    expect(Buffer.from(token1, "base64url").length).toBe(32);

    const token2 = getOrCreatePairToken(tempDir);
    expect(token1).toBe(token2);
  });

  it("rotatePairToken generates a new token and updates file", () => {
    const token1 = getOrCreatePairToken(tempDir);
    const token2 = rotatePairToken(tempDir);
    expect(token2).not.toBe(token1);
    expect(Buffer.from(token2, "base64url").length).toBe(32);

    const token3 = getOrCreatePairToken(tempDir);
    expect(token3).toBe(token2);
  });

  it("enforces mode 600 for pair.token on non-Windows platforms", () => {
    if (process.platform === "win32") return;
    getOrCreatePairToken(tempDir);
    const tokenPath = path.join(tempDir, "pair.token");
    const stat1 = fs.statSync(tokenPath);
    expect((stat1.mode & 0o777).toString(8)).toBe("600");

    rotatePairToken(tempDir);
    const stat2 = fs.statSync(tokenPath);
    expect((stat2.mode & 0o777).toString(8)).toBe("600");
  });
});

describe("Configuration (config.json)", () => {
  let tempDir: string;
  const originalHome = process.env.AUTOOTP_HOME;

  beforeEach(() => {
    const tmpBase = process.env.TMPDIR || process.env.TEMP || "/tmp";
    tempDir = fs.mkdtempSync(path.join(tmpBase, "autootp-config-test-"));
    process.env.AUTOOTP_HOME = tempDir;
  });

  afterEach(() => {
    if (originalHome !== undefined) {
      process.env.AUTOOTP_HOME = originalHome;
    } else {
      delete process.env.AUTOOTP_HOME;
    }
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("loads default configuration when config.json does not exist", () => {
    const cfg = loadConfig(tempDir);
    expect(cfg).toEqual({
      allowedOrigins: [],
      port: 47821,
      pollMs: 3000,
      historyRetention: "5m"
    });
  });

  it("validates valid configurations (good cases)", () => {
    const goodCases = [
      { allowedOrigins: [], port: 1024, pollMs: 1 },
      { allowedOrigins: [], port: 65535, pollMs: 10000 },
      { allowedOrigins: ["chrome-extension://abcdefghijklmnopabcdefghijklmnop"], port: 47821, pollMs: 3000 },
      {
        allowedOrigins: [
          `chrome-extension://${"a".repeat(32)}`,
          `chrome-extension://${"p".repeat(32)}`
        ],
        port: 8080,
        pollMs: 500
      }
    ];

    for (const c of goodCases) {
      expect(() => validateConfig(c)).not.toThrow();
    }
  });

  it("rejects invalid configurations (bad cases)", () => {
    const badCases = [
      { port: 1023, pollMs: 3000, allowedOrigins: [] }, // port < 1024
      { port: 65536, pollMs: 3000, allowedOrigins: [] }, // port > 65535
      { port: 47821.5, pollMs: 3000, allowedOrigins: [] }, // non-integer port
      { port: "47821", pollMs: 3000, allowedOrigins: [] }, // port not a number
      { port: 47821, pollMs: 0, allowedOrigins: [] }, // pollMs <= 0
      { port: 47821, pollMs: -100, allowedOrigins: [] }, // negative pollMs
      { port: 47821, pollMs: 3000, allowedOrigins: "not-an-array" }, // allowedOrigins not array
      { port: 47821, pollMs: 3000, allowedOrigins: ["http://localhost:3000"] }, // invalid scheme
      { port: 47821, pollMs: 3000, allowedOrigins: [`chrome-extension://${"q".repeat(32)}`] }, // invalid char 'q'
      { port: 47821, pollMs: 3000, allowedOrigins: [`chrome-extension://${"A".repeat(32)}`] }, // uppercase
      { port: 47821, pollMs: 3000, allowedOrigins: [`chrome-extension://${"a".repeat(31)}`] }, // length 31
      { port: 47821, pollMs: 3000, allowedOrigins: [`chrome-extension://${"a".repeat(33)}`] }, // length 33
      null,
      undefined,
      [],
      "config"
    ];

    for (const c of badCases) {
      expect(() => validateConfig(c)).toThrow(/Invalid configuration/);
    }
  });

  it("saves and loads configuration with mode 600 on non-Windows", () => {
    const customConfig = {
      allowedOrigins: [`chrome-extension://${"b".repeat(32)}`],
      port: 12345,
      pollMs: 1500,
      historyRetention: "5m" as const
    };

    saveConfig(customConfig, tempDir);
    const loaded = loadConfig(tempDir);
    expect(loaded).toEqual(customConfig);

    if (process.platform !== "win32") {
      const stat = fs.statSync(path.join(tempDir, "config.json"));
      expect((stat.mode & 0o777).toString(8)).toBe("600");
    }
  });

  it("rejects invalid historyRetention configuration values", () => {
    const invalidRetentions = ["10m", "2h", "always", 300, null, true, {}];
    for (const val of invalidRetentions) {
      expect(() =>
        validateConfig({
          allowedOrigins: [],
          port: 47821,
          pollMs: 3000,
          historyRetention: val
        })
      ).toThrow(/Invalid configuration/);
    }
  });
});

describe("OTP History Store (HistoryStore)", () => {
  let tempDir: string;
  const originalHome = process.env.AUTOOTP_HOME;

  beforeEach(() => {
    const tmpBase = process.env.TMPDIR || process.env.TEMP || "/tmp";
    tempDir = fs.mkdtempSync(path.join(tmpBase, "autootp-history-test-"));
    process.env.AUTOOTP_HOME = tempDir;
  });

  afterEach(() => {
    if (originalHome !== undefined) {
      process.env.AUTOOTP_HOME = originalHome;
    } else {
      delete process.env.AUTOOTP_HOME;
    }
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("fails with a clear message if node:sqlite cannot be imported", () => {
    expect(() =>
      ensureSqliteSupported(() => {
        throw new Error("Cannot find module node:sqlite");
      })
    ).toThrow("Node 22.13 or newer is required");

    expect(
      () =>
        new HistoryStore({
          homeDir: tempDir,
          sqliteLoader: () => {
            throw new Error("Cannot find module node:sqlite");
          }
        })
    ).toThrow("Node 22.13 or newer is required");
  });

  it("performs add and list round trip (newest first, decrypted)", () => {
    const store = new HistoryStore(tempDir);
    store.add({
      sender: "GitHub",
      senderDomain: "github.com",
      alias: "work",
      code: "GH1234",
      receivedAt: 1000
    });
    store.add({
      sender: "Google",
      senderDomain: "google.com",
      alias: "personal",
      code: "GO9876",
      receivedAt: 2000
    });

    const entries = store.list();
    expect(entries).toHaveLength(2);
    // Newest first
    expect(entries[0].sender).toBe("Google");
    expect(entries[0].code).toBe("GO9876");
    expect(entries[0].alias).toBe("personal");
    expect(entries[0].receivedAt).toBe(2000);

    expect(entries[1].sender).toBe("GitHub");
    expect(entries[1].code).toBe("GH1234");
    expect(entries[1].alias).toBe("work");
    expect(entries[1].receivedAt).toBe(1000);

    store.close();
  });

  it("purges by each retention value with an injectable clock", () => {
    // Test "5m" (300,000 ms)
    const store5m = new HistoryStore({ homeDir: tempDir, retention: "5m" });
    const now5m = 1_000_000;
    store5m.add({
      sender: "Recent",
      senderDomain: "a.com",
      alias: "a",
      code: "1111",
      receivedAt: now5m - 200_000 // 3.3m ago -> keep
    });
    store5m.add({
      sender: "Old",
      senderDomain: "b.com",
      alias: "b",
      code: "2222",
      receivedAt: now5m - 350_000 // 5.8m ago -> purge
    });
    const purged5m = store5m.purge(now5m);
    expect(purged5m).toBe(1);
    const list5m = store5m.list();
    expect(list5m).toHaveLength(1);
    expect(list5m[0].sender).toBe("Recent");
    store5m.clear();
    store5m.close();

    // Test "30m" (1,800,000 ms)
    const store30m = new HistoryStore({ homeDir: tempDir, retention: "30m" });
    const now30m = 5_000_000;
    store30m.add({
      sender: "Recent30",
      senderDomain: "c.com",
      alias: "c",
      code: "3333",
      receivedAt: now30m - 1_500_000 // 25m ago -> keep
    });
    store30m.add({
      sender: "Old30",
      senderDomain: "d.com",
      alias: "d",
      code: "4444",
      receivedAt: now30m - 2_000_000 // 33m ago -> purge
    });
    const purged30m = store30m.purge(now30m);
    expect(purged30m).toBe(1);
    const list30m = store30m.list();
    expect(list30m.map((e) => e.sender)).toEqual(["Recent30"]);
    store30m.clear();
    store30m.close();

    // Test "1h" (3,600,000 ms)
    const store1h = new HistoryStore({ homeDir: tempDir, retention: "1h" });
    const now1h = 10_000_000;
    store1h.add({
      sender: "Recent1h",
      senderDomain: "e.com",
      alias: "e",
      code: "5555",
      receivedAt: now1h - 3_000_000 // 50m ago -> keep
    });
    store1h.add({
      sender: "Old1h",
      senderDomain: "f.com",
      alias: "f",
      code: "6666",
      receivedAt: now1h - 4_000_000 // 66m ago -> purge
    });
    const purged1h = store1h.purge(now1h);
    expect(purged1h).toBe(1);
    const list1h = store1h.list();
    expect(list1h.map((e) => e.sender)).toEqual(["Recent1h"]);
    store1h.clear();
    store1h.close();

    // Test "off" (purge deletes everything)
    const storeOff = new HistoryStore({ homeDir: tempDir, retention: "off" });
    // Temporarily insert using a 5m store to test off purge
    const storeHelper = new HistoryStore({ homeDir: tempDir, retention: "5m" });
    storeHelper.add({
      sender: "ToPurge",
      senderDomain: "g.com",
      alias: "g",
      code: "7777",
      receivedAt: Date.now()
    });
    storeHelper.close();

    expect(storeOff.list()).toHaveLength(1);
    const purgedOff = storeOff.purge();
    expect(purgedOff).toBe(1);
    expect(storeOff.list()).toHaveLength(0);
    storeOff.close();
  });

  it("'off' stores nothing and purge deletes everything", () => {
    const store = new HistoryStore({ homeDir: tempDir, retention: "off" });
    store.add({
      sender: "GitHub",
      senderDomain: "github.com",
      alias: "personal",
      code: "SECRET",
      receivedAt: Date.now()
    });

    expect(store.list()).toHaveLength(0);
    expect(store.purge()).toBe(0);
    store.close();
  });

  it("the encrypted column does not contain the plaintext code (read raw db file bytes)", () => {
    const store = new HistoryStore(tempDir);
    const plainCode = "TOPSECRET_OTP_987654";
    store.add({
      sender: "BankOfAmerica",
      senderDomain: "bankofamerica.com",
      alias: "personal",
      code: plainCode,
      receivedAt: Date.now()
    });
    store.close();

    const dbPath = path.join(tempDir, "history.db");
    const rawBytes = fs.readFileSync(dbPath);
    expect(rawBytes.includes(plainCode)).toBe(false);
  });

  it("sets db file mode to 600 on non-Windows", () => {
    const store = new HistoryStore(tempDir);
    store.close();

    if (process.platform !== "win32") {
      const dbPath = path.join(tempDir, "history.db");
      const stat = fs.statSync(dbPath);
      expect((stat.mode & 0o777).toString(8)).toBe("600");
    }
  });

  it("ensures secure_delete is ON", () => {
    const store = new HistoryStore(tempDir);
    const db = (store as any).getDb();
    const row = db.prepare("PRAGMA secure_delete;").get() as { secure_delete: number };
    expect(row.secure_delete).toBe(1);
    store.close();
  });

  it("clear() empties the table and runs vacuum", () => {
    const store = new HistoryStore(tempDir);
    store.add({
      sender: "A",
      senderDomain: "a.com",
      alias: "personal",
      code: "111",
      receivedAt: Date.now()
    });
    store.add({
      sender: "B",
      senderDomain: "b.com",
      alias: "personal",
      code: "222",
      receivedAt: Date.now()
    });

    expect(store.list()).toHaveLength(2);
    const count = store.clear();
    expect(count).toBe(2);
    expect(store.list()).toHaveLength(0);
    store.close();
  });
});


