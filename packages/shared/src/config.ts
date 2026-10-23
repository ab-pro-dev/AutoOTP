import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { getHomeDir, ensureHomeDir } from "./paths.js";

export type HistoryRetention = "off" | "5m" | "30m" | "1h";

export const VALID_HISTORY_RETENTIONS: ReadonlySet<string> = new Set([
  "off",
  "5m",
  "30m",
  "1h"
]);

export type NotificationMode = "off" | "hidden" | "code";

export const VALID_NOTIFICATION_MODES: ReadonlySet<string> = new Set([
  "off",
  "hidden",
  "code"
]);

export interface AutoOtpConfig {
  allowedOrigins: string[];
  port: number;
  pollMs: number;
  historyRetention: HistoryRetention;
  notifications: NotificationMode;
}

export const DEFAULT_CONFIG: Readonly<AutoOtpConfig> = Object.freeze({
  allowedOrigins: [],
  port: 47821,
  pollMs: 3000,
  historyRetention: "5m",
  notifications: "code"
});

export const CHROME_EXTENSION_ORIGIN_REGEX = /^chrome-extension:\/\/[a-p]{32}$/;

/**
 * Validates the AutoOTP configuration schema and values.
 * Throws a descriptive error if the configuration is invalid.
 */
export function validateConfig(config: unknown): asserts config is AutoOtpConfig {
  if (!config || typeof config !== "object" || Array.isArray(config)) {
    throw new Error("Invalid configuration: configuration must be an object");
  }

  const c = config as Record<string, unknown>;

  if (typeof c.port !== "number" || !Number.isInteger(c.port) || c.port < 1024 || c.port > 65535) {
    throw new Error(
      `Invalid configuration: port must be an integer between 1024 and 65535, got ${String(c.port)}`
    );
  }

  if (typeof c.pollMs !== "number" || !Number.isFinite(c.pollMs) || c.pollMs <= 0) {
    throw new Error(
      `Invalid configuration: pollMs must be a positive number, got ${String(c.pollMs)}`
    );
  }

  if (!Array.isArray(c.allowedOrigins)) {
    throw new Error("Invalid configuration: allowedOrigins must be an array of strings");
  }

  for (const origin of c.allowedOrigins) {
    if (typeof origin !== "string" || !CHROME_EXTENSION_ORIGIN_REGEX.test(origin)) {
      throw new Error(
        `Invalid configuration: origin "${String(origin)}" must match ^chrome-extension://[a-p]{32}$`
      );
    }
  }

  if (c.historyRetention !== undefined) {
    if (
      typeof c.historyRetention !== "string" ||
      !VALID_HISTORY_RETENTIONS.has(c.historyRetention)
    ) {
      throw new Error(
        `Invalid configuration: historyRetention must be one of 'off', '5m', '30m', '1h', got ${String(c.historyRetention)}`
      );
    }
  }

  if (c.notifications !== undefined) {
    if (
      typeof c.notifications !== "string" ||
      !VALID_NOTIFICATION_MODES.has(c.notifications)
    ) {
      throw new Error(
        `Invalid configuration: notifications must be one of 'off', 'hidden', 'code', got ${String(c.notifications)}`
      );
    }
  }
}

/**
 * Loads the AutoOTP configuration from <home>/config.json.
 * If the file does not exist, returns default configuration.
 * If the file contains invalid configuration, throws a clear error.
 */
export function loadConfig(homeDir: string = getHomeDir()): AutoOtpConfig {
  ensureHomeDir(homeDir);
  const configPath = path.join(homeDir, "config.json");

  if (!fs.existsSync(configPath)) {
    return {
      allowedOrigins: [...DEFAULT_CONFIG.allowedOrigins],
      port: DEFAULT_CONFIG.port,
      pollMs: DEFAULT_CONFIG.pollMs,
      historyRetention: DEFAULT_CONFIG.historyRetention,
      notifications: DEFAULT_CONFIG.notifications
    };
  }

  const raw = fs.readFileSync(configPath, "utf8");
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Failed to parse configuration file at ${configPath}: ${(err as Error).message}`);
  }

  validateConfig(parsed);

  return {
    allowedOrigins: [...parsed.allowedOrigins],
    port: parsed.port,
    pollMs: parsed.pollMs,
    historyRetention: parsed.historyRetention ?? DEFAULT_CONFIG.historyRetention,
    notifications: parsed.notifications ?? DEFAULT_CONFIG.notifications
  };
}

/**
 * Validates and atomically saves the configuration to <home>/config.json with mode 0o600.
 */
export function saveConfig(
  config: Partial<AutoOtpConfig>,
  homeDir: string = getHomeDir()
): AutoOtpConfig {
  ensureHomeDir(homeDir);
  const configPath = path.join(homeDir, "config.json");

  const current = fs.existsSync(configPath) ? loadConfig(homeDir) : DEFAULT_CONFIG;
  const merged: AutoOtpConfig = {
    allowedOrigins: config.allowedOrigins ?? [...current.allowedOrigins],
    port: config.port ?? current.port,
    pollMs: config.pollMs ?? current.pollMs,
    historyRetention: config.historyRetention ?? current.historyRetention,
    notifications: config.notifications ?? current.notifications
  };

  validateConfig(merged);

  const content = JSON.stringify(merged, null, 2) + "\n";
  const tempPath = path.join(
    homeDir,
    `.config.json.${crypto.randomBytes(6).toString("hex")}.tmp`
  );

  fs.writeFileSync(tempPath, content, { mode: 0o600 });
  if (process.platform !== "win32") {
    fs.chmodSync(tempPath, 0o600);
  }

  fs.renameSync(tempPath, configPath);
  if (process.platform !== "win32") {
    fs.chmodSync(configPath, 0o600);
  }

  return merged;
}
