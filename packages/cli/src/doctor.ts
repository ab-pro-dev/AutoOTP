import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  getHomeDir,
  loadConfig,
  TokenStore,
  readStatus,
  isStatusFresh,
  VERSION
} from "@autootp/shared";
import { refreshAccessToken, ReauthRequiredError } from "@autootp/gmail";
import { defaultExecFile, ExecFunction, checkPortListening } from "./autostart.js";
import { CommandContext } from "./commands.js";

export interface DoctorContext extends CommandContext {
  execFn?: ExecFunction;
  platform?: NodeJS.Platform;
  now?: () => number;
  nodeVersion?: string;
  checkPortListening?: (port: number) => Promise<boolean>;
  exitImpl?: (code: number) => void;
  unitDir?: string;
}

/**
 * Runs diagnostic checks on the AutoOTP system and reports OK / WARN / FAIL.
 * Exits with code 1 if any check is FAIL.
 */
export async function doctorAction(context: DoctorContext = {}): Promise<void> {
  const homeDir = context.homeDir ?? getHomeDir();
  const platform = context.platform ?? process.platform;
  const execFn = context.execFn ?? defaultExecFile;
  const now = context.now ? context.now() : Date.now();
  const exit = context.exitImpl ?? process.exit;

  let hasFail = false;

  const record = (status: "OK" | "WARN" | "FAIL", message: string) => {
    if (status === "FAIL") {
      hasFail = true;
    }
    console.log(`${status} ${message}`);
  };

  // 1. Node version at least 22.13
  const nodeVer = context.nodeVersion ?? process.versions.node;
  const cleanVer = nodeVer.replace(/^v/, "");
  const [major, minor] = cleanVer.split(".").map((n) => parseInt(n, 10));
  if (major > 22 || (major === 22 && minor >= 13)) {
    record("OK", `Node.js version ${nodeVer}`);
  } else {
    record("FAIL", `Node.js version ${nodeVer} (requires >= 22.13)`);
  }

  // 2. config.json is valid
  const configPath = path.join(homeDir, "config.json");
  let config: any = null;
  if (fs.existsSync(configPath)) {
    try {
      config = loadConfig(homeDir);
      record("OK", "config.json is valid");
    } catch (err: any) {
      record("FAIL", `config.json invalid: ${err.message}`);
    }
  } else {
    try {
      config = loadConfig(homeDir);
      record("OK", "config.json valid (defaults)");
    } catch (err: any) {
      record("FAIL", `config.json invalid: ${err.message}`);
    }
  }

  // 3. credentials.json exists with mode 600 (non-Windows)
  const credPath = path.join(homeDir, "credentials.json");
  if (!fs.existsSync(credPath)) {
    record("FAIL", "credentials.json missing");
  } else if (platform !== "win32") {
    try {
      const mode = fs.statSync(credPath).mode & 0o777;
      if (mode === 0o600) {
        record("OK", "credentials.json exists with mode 600");
      } else {
        record("FAIL", `credentials.json mode is 0o${mode.toString(8)}, expected 0o600`);
      }
    } catch {
      record("FAIL", "credentials.json stat failed");
    }
  } else {
    record("OK", "credentials.json exists");
  }

  // 4. key, tokens.enc and history.db have mode 600 when they exist
  if (platform === "win32") {
    record("OK", "key, tokens.enc, history.db permissions (Windows)");
  } else {
    const secFiles = ["key", "tokens.enc", "history.db"];
    let secOk = true;
    const badModes: string[] = [];
    for (const file of secFiles) {
      const filePath = path.join(homeDir, file);
      if (fs.existsSync(filePath)) {
        const mode = fs.statSync(filePath).mode & 0o777;
        if (mode !== 0o600) {
          secOk = false;
          badModes.push(`${file} (0o${mode.toString(8)})`);
        }
      }
    }
    if (secOk) {
      record("OK", "key, tokens.enc and history.db have mode 600 when they exist");
    } else {
      record("FAIL", `Permissions incorrect for: ${badModes.join(", ")}, expected 0o600`);
    }
  }

  // 5. at least one account; for EACH account, try refreshAccessToken: OK, FAIL "expired: run autootp login <alias>" on ReauthRequiredError, WARN on a network error
  const store = new TokenStore(homeDir);
  let aliases: string[] = [];
  try {
    aliases = await store.list();
  } catch {}

  if (aliases.length === 0) {
    record("FAIL", "No accounts connected. Run: autootp login");
  } else {
    for (const alias of aliases) {
      try {
        await refreshAccessToken(alias, {
          homeDir,
          fetchImpl: context.fetchImpl
        });
        record("OK", `Account "${alias}" refresh token is valid`);
      } catch (err: any) {
        if (err instanceof ReauthRequiredError || err.name === "ReauthRequiredError") {
          record("FAIL", `Account "${alias}" expired: run autootp login ${alias}`);
        } else {
          record("WARN", `Account "${alias}" refresh network error: ${err.message}`);
        }
      }
    }
  }

  // 6. at least one paired extension
  const pairedCount = (config?.allowedOrigins || []).length;
  if (pairedCount > 0) {
    record("OK", `${pairedCount} paired extension(s)`);
  } else {
    record("FAIL", "No extension paired. Run: autootp pair <extensionId>");
  }

  // 7. service installed and running (Linux via systemctl --user; other platforms WARN "not supported")
  if (platform === "linux") {
    const unitDir = context.unitDir ?? path.join(os.homedir(), ".config", "systemd", "user");
    const unitPath = path.join(unitDir, "autootp.service");
    if (!fs.existsSync(unitPath)) {
      record("FAIL", "Service not installed. Run: autootp enable");
    } else {
      try {
        const { stdout } = await execFn("systemctl", ["--user", "is-active", "autootp.service"]);
        if (stdout.trim() === "active") {
          record("OK", "Service is installed and running");
        } else {
          record("FAIL", `Service installed but not running (${stdout.trim()})`);
        }
      } catch (err: any) {
        const out = err?.stdout?.toString().trim();
        if (out === "active") {
          record("OK", "Service is installed and running");
        } else {
          record("FAIL", "Service installed but not running");
        }
      }
    }
  } else {
    record("WARN", `Service check not supported on ${platform}`);
  }

  // 8. port listening
  const port = config?.port || 47821;
  const isListening = context.checkPortListening
    ? await context.checkPortListening(port)
    : await checkPortListening(port);
  if (isListening) {
    record("OK", `Port ${port} is listening`);
  } else {
    record("FAIL", `Port ${port} is not listening`);
  }

  // 9. status file fresh
  const status = readStatus(homeDir);
  const statusFresh = isStatusFresh(status, 90000, now);
  if (!status) {
    record("FAIL", "Status file missing (service not running?)");
  } else if (!statusFresh) {
    record("FAIL", `Status file is stale (updated ${Math.floor((now - status.updatedAt) / 1000)}s ago)`);
  } else {
    record("OK", "Status file is fresh");
  }

  // 10. browser extension connected (WARN if not)
  if (status && statusFresh && status.authedClients > 0) {
    record("OK", `Browser extension connected (${status.authedClients})`);
  } else {
    record("WARN", "Browser extension is not connected");
  }

  // 11. notification tool available (notify-send on Linux, WARN if missing)
  if (platform === "linux") {
    try {
      await execFn("which", ["notify-send"]);
      record("OK", "Notification tool available (notify-send)");
    } catch {
      record("WARN", "Notification tool missing (notify-send not found)");
    }
  } else if (platform === "darwin") {
    try {
      await execFn("which", ["osascript"]);
      record("OK", "Notification tool available (osascript)");
    } catch {
      record("WARN", "Notification tool missing (osascript not found)");
    }
  } else {
    record("WARN", `Desktop notifications not supported on ${platform}`);
  }

  // 12. last line: version
  console.log(`Version: ${VERSION}`);

  if (hasFail) {
    exit(1);
  }
}
