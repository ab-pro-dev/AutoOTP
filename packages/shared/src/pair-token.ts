import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { getHomeDir, ensureHomeDir } from "./paths.js";

/**
 * Returns the existing pairing token, or generates a fresh 32-byte base64url token on first use.
 * Stored at <home>/pair.token with mode 0o600.
 * Created with flag "wx" and never overwrites an existing token on get.
 */
export function getOrCreatePairToken(homeDir: string = getHomeDir()): string {
  ensureHomeDir(homeDir);
  const tokenPath = path.join(homeDir, "pair.token");

  if (!fs.existsSync(tokenPath)) {
    const newToken = crypto.randomBytes(32).toString("base64url");
    try {
      fs.writeFileSync(tokenPath, newToken, { flag: "wx", mode: 0o600 });
      if (process.platform !== "win32") {
        fs.chmodSync(tokenPath, 0o600);
      }
      return newToken;
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException)?.code !== "EEXIST") {
        throw err;
      }
    }
  }

  const existing = fs.readFileSync(tokenPath, "utf8").trim();
  return existing;
}

/**
 * Generates a fresh 32-byte base64url pairing token and atomically writes it to <home>/pair.token with mode 0o600.
 */
export function rotatePairToken(homeDir: string = getHomeDir()): string {
  ensureHomeDir(homeDir);
  const tokenPath = path.join(homeDir, "pair.token");
  const newToken = crypto.randomBytes(32).toString("base64url");

  const tempPath = path.join(
    homeDir,
    `.pair.token.${crypto.randomBytes(6).toString("hex")}.tmp`
  );

  fs.writeFileSync(tempPath, newToken, { mode: 0o600 });
  if (process.platform !== "win32") {
    fs.chmodSync(tempPath, 0o600);
  }
  fs.renameSync(tempPath, tokenPath);
  if (process.platform !== "win32") {
    fs.chmodSync(tokenPath, 0o600);
  }

  return newToken;
}
