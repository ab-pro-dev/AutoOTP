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
  rotatePairToken
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

