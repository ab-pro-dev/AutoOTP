import { execFile } from "node:child_process";
import { promisify } from "node:util";
import {
  loadConfig,
  getHomeDir,
  AutoOtpConfig,
  NotificationMode
} from "@autootp/shared";

const defaultExecFile = promisify(execFile);

export type ExecFunction = (
  file: string,
  args: string[]
) => Promise<unknown> | unknown;

// experimental, untested on a real Mac
export const MACOS_NOTIFICATION_SCRIPT =
  "on run argv\n  display notification (item 2 of argv) with title (item 1 of argv)\nend run";

/**
 * Sanitizes notification text by removing control characters, newlines,
 * replacing < > & with spaces, collapsing whitespace, trimming, stripping leading dashes,
 * and cutting to max characters. Returns "Unknown sender" if empty.
 */
export function sanitizeNotificationText(text: string, max: number = 40): string {
  if (!text || typeof text !== "string") {
    return "Unknown sender";
  }

  let cleaned = text
    .replace(/[\x00-\x1f\x7f]/g, "")
    .replace(/[<>&]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/^[- ]+/, "")
    .trim();

  if (cleaned.length > max) {
    cleaned = cleaned.slice(0, max).trim();
  }

  if (!cleaned) {
    return "Unknown sender";
  }

  return cleaned;
}

export interface DesktopNotifierOptions {
  homeDir?: string;
  platform?: NodeJS.Platform;
  execFn?: ExecFunction;
  now?: () => number;
  config?: AutoOtpConfig;
}

export class DesktopNotifier {
  private readonly homeDir: string;
  private readonly platform: NodeJS.Platform;
  private readonly execFn: ExecFunction;
  private readonly now: () => number;
  private readonly initialConfig?: AutoOtpConfig;
  private readonly lastExpiryAlerts = new Map<string, number>();

  constructor(options: DesktopNotifierOptions = {}) {
    this.homeDir = options.homeDir ?? getHomeDir();
    this.platform = options.platform ?? process.platform;
    this.execFn = options.execFn ?? defaultExecFile;
    this.now = options.now ?? (() => Date.now());
    this.initialConfig = options.config;
  }

  private getMode(): NotificationMode {
    try {
      const cfg = loadConfig(this.homeDir);
      return cfg.notifications ?? "code";
    } catch {
      return this.initialConfig?.notifications ?? "code";
    }
  }

  async send(title: string, body: string): Promise<void> {
    const platform = this.platform;

    if (platform === "linux") {
      try {
        await this.execFn("notify-send", [
          "-a",
          "AutoOTP",
          "-t",
          "15000",
          "-h",
          "int:transient:1",
          "--",
          title,
          body
        ]);
      } catch {
        // Failures of the notification command (missing binary, no session bus) are caught and ignored.
        // They must never block OTP delivery.
      }
      return;
    }

    if (platform === "darwin") {
      // experimental, untested on a real Mac
      try {
        await this.execFn("osascript", [
          "-e",
          MACOS_NOTIFICATION_SCRIPT,
          title,
          body
        ]);
      } catch {
        // Failures of the notification command (missing binary, no session bus) are caught and ignored.
        // They must never block OTP delivery.
      }
      return;
    }

    if (platform === "win32") {
      // Windows: do nothing and never throw.
      return;
    }

    // Other platforms: do nothing and never throw.
  }

  async notifyOtp(sender: string, code: string): Promise<void> {
    const mode = this.getMode();
    if (mode === "off") {
      return;
    }

    const sanitizedSender = sanitizeNotificationText(sender);
    const title = `AutoOTP: ${sanitizedSender}`;
    const body = mode === "code" ? `Code: ${code}` : "New code received";

    await this.send(title, body);
  }

  async notifyExpiry(alias: string): Promise<void> {
    const mode = this.getMode();
    if (mode === "off") {
      return;
    }

    const SIX_HOURS_MS = 6 * 60 * 60 * 1000;
    const currentTime = this.now();
    const lastAlert = this.lastExpiryAlerts.get(alias);
    if (lastAlert !== undefined && currentTime - lastAlert < SIX_HOURS_MS) {
      return;
    }

    this.lastExpiryAlerts.set(alias, currentTime);

    const sanitizedAlias = sanitizeNotificationText(alias);
    const title = `AutoOTP: Google access expired for ${sanitizedAlias}`;
    const body = `Run: autootp login ${sanitizedAlias}`;

    await this.send(title, body);
  }
}
