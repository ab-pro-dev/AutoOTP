import fs from "node:fs";
import path from "node:path";

/**
 * Returns the AutoOTP home directory path.
 * Uses AUTOOTP_HOME environment variable if set, otherwise ~/.autootp.
 */
export function getHomeDir(): string {
  if (process.env.AUTOOTP_HOME && process.env.AUTOOTP_HOME.trim().length > 0) {
    return process.env.AUTOOTP_HOME;
  }
  const userHome = process.env.HOME || process.env.USERPROFILE || "";
  return path.join(userHome, ".autootp");
}

/**
 * Ensures the AutoOTP home directory and its logs/ subfolder exist with mode 0o700.
 */
export function ensureHomeDir(dir: string = getHomeDir()): string {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  if (process.platform !== "win32") {
    fs.chmodSync(dir, 0o700);
  }

  const logsDir = path.join(dir, "logs");
  if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true, mode: 0o700 });
  }
  if (process.platform !== "win32") {
    fs.chmodSync(logsDir, 0o700);
  }

  return dir;
}
