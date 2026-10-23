import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { getHomeDir, ensureHomeDir } from "./paths.js";
import { VERSION } from "./version.js";

export type AccountStatus = "ok" | "expired" | "error";

export interface StatusLastOtp {
  sender: string;
  senderDomain: string | null;
  at: number;
}

export interface AutoOtpStatus {
  v: 1;
  pid: number;
  version: string;
  startedAt: number;
  updatedAt: number;
  port: number;
  authedClients: number;
  accounts: Record<string, AccountStatus>;
  lastOtp: StatusLastOtp | null;
}

/**
 * Atomically writes AutoOTP status to <home>/status.json with mode 0o600.
 * Enforces that no code, token, or secret can ever be written.
 */
export function writeStatus(
  status: AutoOtpStatus,
  homeDir: string = getHomeDir()
): void {
  // Defensive guard: status must NEVER contain a code or token
  const statusAny = status as any;
  if ("code" in statusAny || (status.lastOtp && "code" in (status.lastOtp as any))) {
    throw new Error("Security violation: status file must NEVER contain an OTP code");
  }
  if ("token" in statusAny || "pairToken" in statusAny) {
    throw new Error("Security violation: status file must NEVER contain a token");
  }

  ensureHomeDir(homeDir);
  const statusPath = path.join(homeDir, "status.json");

  // Build clean object with exact schema keys and order
  const sanitized: AutoOtpStatus = {
    v: 1,
    pid: status.pid,
    version: status.version || VERSION,
    startedAt: status.startedAt,
    updatedAt: status.updatedAt,
    port: status.port,
    authedClients: status.authedClients,
    accounts: { ...status.accounts },
    lastOtp: status.lastOtp
      ? {
          sender: status.lastOtp.sender,
          senderDomain: status.lastOtp.senderDomain ?? null,
          at: status.lastOtp.at
        }
      : null
  };

  const content = JSON.stringify(sanitized, null, 2) + "\n";
  const tempPath = path.join(
    homeDir,
    `.status.json.${crypto.randomBytes(6).toString("hex")}.tmp`
  );

  fs.writeFileSync(tempPath, content, { mode: 0o600 });
  if (process.platform !== "win32") {
    fs.chmodSync(tempPath, 0o600);
  }

  fs.renameSync(tempPath, statusPath);
  if (process.platform !== "win32") {
    fs.chmodSync(statusPath, 0o600);
  }
}

/**
 * Reads AutoOTP status from <home>/status.json.
 * Returns null if the file does not exist, cannot be read, or is invalid.
 */
export function readStatus(homeDir: string = getHomeDir()): AutoOtpStatus | null {
  try {
    const statusPath = path.join(homeDir, "status.json");
    if (!fs.existsSync(statusPath)) {
      return null;
    }
    const raw = fs.readFileSync(statusPath, "utf8");
    const parsed = JSON.parse(raw);
    if (
      !parsed ||
      typeof parsed !== "object" ||
      parsed.v !== 1 ||
      typeof parsed.pid !== "number" ||
      typeof parsed.updatedAt !== "number" ||
      typeof parsed.port !== "number" ||
      typeof parsed.authedClients !== "number" ||
      typeof parsed.accounts !== "object" ||
      parsed.accounts === null
    ) {
      return null;
    }
    return parsed as AutoOtpStatus;
  } catch {
    return null;
  }
}

/**
 * Removes the status file on graceful shutdown.
 */
export function deleteStatus(homeDir: string = getHomeDir()): void {
  try {
    const statusPath = path.join(homeDir, "status.json");
    if (fs.existsSync(statusPath)) {
      fs.unlinkSync(statusPath);
    }
  } catch {}
}

/**
 * Checks whether the status file was updated within maxAgeMs (default: 90 seconds).
 */
export function isStatusFresh(
  status: AutoOtpStatus | null,
  maxAgeMs: number = 90000,
  now: number = Date.now()
): boolean {
  if (!status) return false;
  return now - status.updatedAt <= maxAgeMs;
}
