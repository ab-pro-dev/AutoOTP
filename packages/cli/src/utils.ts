import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { getHomeDir } from "@autootp/shared";

/**
 * Validates an account alias.
 * Must consist of lowercase letters, digits, and hyphens, 1-32 chars.
 */
export function validateAlias(alias: string): void {
  if (!alias || typeof alias !== "string" || !/^[a-z0-9-]{1,32}$/.test(alias)) {
    throw new Error(
      `Invalid alias "${alias}". Alias must be 1-32 characters long and contain only lowercase letters, digits, and hyphens.`
    );
  }
}

/**
 * Validates a Chrome extension ID.
 * Must consist of exactly 32 characters in the range [a-p].
 */
export function validateExtensionId(extensionId: string): void {
  if (!extensionId || typeof extensionId !== "string" || !/^[a-p]{32}$/.test(extensionId)) {
    throw new Error(
      `Invalid extension ID "${extensionId}". Extension ID must be 32 characters long and contain only lowercase letters a-p.`
    );
  }
}


/**
 * Checks if credentials.json is group- or world-readable on non-Windows platforms.
 * Prints a warning to stderr if permissions are overly permissive.
 */
export function checkCredentialsPermissions(homeDir: string = getHomeDir()): void {
  if (process.platform === "win32") return;
  const credsPath = path.join(homeDir, "credentials.json");
  if (!fs.existsSync(credsPath)) return;

  try {
    const stats = fs.statSync(credsPath);
    const mode = stats.mode;
    // Group-readable is 0o040, World-readable is 0o004
    if ((mode & 0o044) !== 0) {
      console.warn(
        `Warning: ${credsPath} is group- or world-readable. Consider running: chmod 600 ${credsPath}`
      );
    }
  } catch {
    // Ignore stat failures
  }
}

/**
 * Attempts to open a URL in the user's default browser.
 * Uses child_process.spawn with an argument array for safe invocation.
 * Ignores opener failures since the printed URL is the fallback.
 */
export function openBrowser(url: string): void {
  let command: string;
  let args: string[];

  if (process.platform === "darwin") {
    command = "open";
    args = [url];
  } else if (process.platform === "win32") {
    command = "rundll32";
    args = ["url.dll,FileProtocolHandler", url];
  } else {
    command = "xdg-open";
    args = [url];
  }

  try {
    const child = spawn(command, args, {
      stdio: "ignore",
      detached: true
    });
    child.on("error", () => {
      // Ignore opener errors
    });
    child.unref();
  } catch {
    // Ignore opener errors
  }
}

export interface AccountEntry {
  alias: string;
  email: string;
  addedAt: number;
}

/**
 * Formats a list of accounts into a readable table, or returns the empty-state message.
 */
export function formatAccountsTable(accounts: AccountEntry[]): string {
  if (accounts.length === 0) {
    return "No accounts connected. Run: autootp login";
  }

  const headers = ["ALIAS", "EMAIL", "ADDED"];
  const rows = accounts.map((acc) => [
    acc.alias,
    acc.email,
    new Date(acc.addedAt).toISOString().slice(0, 19).replace("T", " ")
  ]);

  const colWidths = [
    Math.max(headers[0].length, ...rows.map((r) => r[0].length)),
    Math.max(headers[1].length, ...rows.map((r) => r[1].length)),
    Math.max(headers[2].length, ...rows.map((r) => r[2].length))
  ];

  const headerLine = headers
    .map((h, i) => h.padEnd(colWidths[i]))
    .join("  ");
  const dividerLine = colWidths
    .map((w) => "-".repeat(w))
    .join("  ");
  const dataLines = rows.map((r) =>
    r.map((cell, i) => cell.padEnd(colWidths[i])).join("  ")
  );

  return [headerLine, dividerLine, ...dataLines].join("\n");
}

/**
 * Attempts a best-effort token revocation with Google OAuth revoke endpoint.
 */
export async function revokeToken(
  refreshToken: string,
  fetchImpl: typeof fetch = globalThis.fetch
): Promise<boolean> {
  if (!refreshToken) return false;
  try {
    const res = await fetchImpl("https://oauth2.googleapis.com/revoke", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({ token: refreshToken }).toString()
    });
    return res.ok;
  } catch {
    return false;
  }
}

/**
 * Formats an OTP notification into a single line: [HH:MM:SS] <sender> (<alias>) -> <code>
 * In non-TTY environments (or when maskCode is true), the code is masked with asterisks of the same length.
 */
export function formatOtpNotification(otp: {
  accountId?: string;
  account?: string;
  sender: string;
  code: string;
  receivedAt?: number;
  maskCode?: boolean;
}): string {
  const d = new Date(otp.receivedAt || Date.now());
  const pad = (n: number) => String(n).padStart(2, "0");
  const time = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  const acct = otp.accountId ?? otp.account ?? "unknown";
  const shouldMask = otp.maskCode ?? (!process.stdout?.isTTY);
  const displayCode = shouldMask ? "*".repeat(otp.code.length) : otp.code;
  return `[${time}] ${otp.sender} (${acct}) -> ${displayCode}`;
}

