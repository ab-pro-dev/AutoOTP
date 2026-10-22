import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { getHomeDir, ensureHomeDir } from "./paths.js";

export interface StoredTokens {
  refreshToken: string;
  email: string;
  addedAt: number;
}

export interface EncryptedPayload {
  v: 1;
  iv: string;
  tag: string;
  data: string;
}

/**
 * Encrypts a plaintext string using AES-256-GCM with a fresh 12-byte IV.
 * Returns the payload serialized as JSON containing base64 fields.
 */
export function encryptPayload(plaintext: string, key: Buffer): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([
    cipher.update(Buffer.from(plaintext, "utf8")),
    cipher.final()
  ]);
  const tag = cipher.getAuthTag();

  const payload: EncryptedPayload = {
    v: 1,
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    data: encrypted.toString("base64")
  };
  return JSON.stringify(payload);
}

/**
 * Decrypts a base64 JSON payload encrypted with AES-256-GCM.
 */
export function decryptPayload(codeEnc: string, key: Buffer): string {
  let jsonStr = codeEnc;
  if (!jsonStr.startsWith("{")) {
    try {
      jsonStr = Buffer.from(codeEnc, "base64").toString("utf8");
    } catch {}
  }

  let payload: EncryptedPayload;
  try {
    payload = JSON.parse(jsonStr);
  } catch {
    throw new Error("Encrypted payload could not be decrypted");
  }

  if (
    !payload ||
    payload.v !== 1 ||
    typeof payload.iv !== "string" ||
    typeof payload.tag !== "string" ||
    typeof payload.data !== "string"
  ) {
    throw new Error("Encrypted payload could not be decrypted");
  }

  const iv = Buffer.from(payload.iv, "base64");
  const tag = Buffer.from(payload.tag, "base64");
  const data = Buffer.from(payload.data, "base64");

  if (iv.length !== 12 || tag.length !== 16) {
    throw new Error("Encrypted payload could not be decrypted");
  }

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]).toString("utf8");
}

/**
 * Retrieves the encryption key for the given home directory, or creates a new 32-byte key.
 * On first use, generates a 32-byte random key and writes it with flag "wx" and mode 0o600.
 * On subsequent runs, reads the existing key.
 * If the existing key is not exactly 32 bytes, throws an error.
 */
export function getOrCreateKey(homeDir: string = getHomeDir()): Buffer {
  ensureHomeDir(homeDir);
  const keyPath = path.join(homeDir, "key");

  if (!fs.existsSync(keyPath)) {
    const newKey = crypto.randomBytes(32);
    try {
      fs.writeFileSync(keyPath, newKey, { flag: "wx", mode: 0o600 });
      if (process.platform !== "win32") {
        fs.chmodSync(keyPath, 0o600);
      }
      return newKey;
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException)?.code !== "EEXIST") {
        throw err;
      }
    }
  }

  const existingKey = fs.readFileSync(keyPath);
  if (existingKey.length !== 32) {
    throw new Error("Key file must be exactly 32 bytes");
  }

  return existingKey;
}

export class TokenStore {
  private readonly homeDir: string;

  constructor(homeDir?: string) {
    this.homeDir = homeDir ?? getHomeDir();
  }

  private getKey(): Buffer {
    return getOrCreateKey(this.homeDir);
  }

  private getTokensPath(): string {
    return path.join(this.homeDir, "tokens.enc");
  }

  private async readAll(): Promise<Record<string, StoredTokens>> {
    const tokensPath = this.getTokensPath();
    const keyPath = path.join(this.homeDir, "key");

    if (fs.existsSync(keyPath) || fs.existsSync(tokensPath)) {
      this.getKey();
    }

    if (!fs.existsSync(tokensPath)) {
      return {};
    }

    const key = this.getKey();

    let raw: string;
    try {
      raw = fs.readFileSync(tokensPath, "utf8");
    } catch {
      throw new Error("Token store could not be decrypted");
    }

    let payload: EncryptedPayload;
    try {
      payload = JSON.parse(raw);
    } catch {
      throw new Error("Token store could not be decrypted");
    }

    if (
      !payload ||
      payload.v !== 1 ||
      typeof payload.iv !== "string" ||
      typeof payload.tag !== "string" ||
      typeof payload.data !== "string"
    ) {
      throw new Error("Token store could not be decrypted");
    }

    try {
      const iv = Buffer.from(payload.iv, "base64");
      const tag = Buffer.from(payload.tag, "base64");
      const data = Buffer.from(payload.data, "base64");

      if (iv.length !== 12 || tag.length !== 16) {
        throw new Error("Token store could not be decrypted");
      }

      const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
      decipher.setAuthTag(tag);
      const decrypted = Buffer.concat([decipher.update(data), decipher.final()]);
      return JSON.parse(decrypted.toString("utf8"));
    } catch {
      throw new Error("Token store could not be decrypted");
    }
  }

  private async writeAll(data: Record<string, StoredTokens>): Promise<void> {
    ensureHomeDir(this.homeDir);
    const key = this.getKey();
    const tokensPath = this.getTokensPath();

    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
    const plaintext = Buffer.from(JSON.stringify(data), "utf8");
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    const payload: EncryptedPayload = {
      v: 1,
      iv: iv.toString("base64"),
      tag: tag.toString("base64"),
      data: encrypted.toString("base64")
    };

    const content = JSON.stringify(payload, null, 2);
    const tempPath = path.join(
      this.homeDir,
      `.tokens.enc.${crypto.randomBytes(8).toString("hex")}.tmp`
    );

    try {
      fs.writeFileSync(tempPath, content, { mode: 0o600 });
      if (process.platform !== "win32") {
        fs.chmodSync(tempPath, 0o600);
      }
      fs.renameSync(tempPath, tokensPath);
      if (process.platform !== "win32") {
        fs.chmodSync(tokensPath, 0o600);
      }
    } finally {
      if (fs.existsSync(tempPath)) {
        try {
          fs.unlinkSync(tempPath);
        } catch {
          // ignore cleanup errors
        }
      }
    }
  }

  async get(accountId: string): Promise<StoredTokens | null> {
    const data = await this.readAll();
    return data[accountId] ?? null;
  }

  async set(accountId: string, tokens: StoredTokens): Promise<void> {
    const data = await this.readAll();
    data[accountId] = tokens;
    await this.writeAll(data);
  }

  async remove(accountId: string): Promise<boolean> {
    const data = await this.readAll();
    if (!(accountId in data)) {
      return false;
    }
    delete data[accountId];
    await this.writeAll(data);
    return true;
  }

  async list(): Promise<string[]> {
    const data = await this.readAll();
    return Object.keys(data);
  }
}
