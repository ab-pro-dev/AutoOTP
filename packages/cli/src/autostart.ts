import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { execFile, ExecFileOptions } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import {
  getHomeDir,
  loadConfig,
  TokenStore,
  ConfigurationError
} from "@autootp/shared";
import { CommandContext } from "./commands.js";

const defaultExecFile = promisify(execFile);

export type ExecFunction = (
  file: string,
  args: string[],
  options?: ExecFileOptions
) => Promise<{ stdout: string; stderr: string }>;

export interface AutoStartContext extends CommandContext {
  execFn?: ExecFunction;
  platform?: NodeJS.Platform;
  nodePath?: string;
  cliPath?: string;
  autootpHome?: string;
  exitImpl?: (code: number) => void;
  uid?: number;
  checkPortListening?: (port: number) => Promise<boolean>;
  unitDir?: string;
  launchAgentsDir?: string;
}

/**
 * Resolves the absolute path to packages/cli/dist/index.js.
 */
export function getCliDistPath(): string {
  const currentFile = fileURLToPath(import.meta.url);
  const dir = path.dirname(currentFile);
  const inDist = path.resolve(dir, "index.js");
  if (fs.existsSync(inDist)) {
    return inDist;
  }
  const fromSrc = path.resolve(dir, "..", "dist", "index.js");
  if (fs.existsSync(fromSrc)) {
    return fromSrc;
  }
  return inDist;
}

/**
 * Performs a TCP connect test to 127.0.0.1:<port>.
 */
export function checkPortListening(port: number, timeoutMs = 500): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host: "127.0.0.1", port });
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => {
      socket.destroy();
      resolve(true);
    });
    socket.once("timeout", () => {
      socket.destroy();
      resolve(false);
    });
    socket.once("error", () => {
      socket.destroy();
      resolve(false);
    });
  });
}

/**
 * Generates a systemd user service unit file.
 * - Double-quotes node and CLI paths
 * - Escapes every "%" as "%%"
 * - Refuses paths containing newlines
 * - Emits Environment=AUTOOTP_HOME only if set
 */
export function generateSystemdUnit(options: {
  nodePath: string;
  cliPath: string;
  autootpHome?: string;
}): string {
  const { nodePath, cliPath, autootpHome } = options;

  if (nodePath.includes("\n") || nodePath.includes("\r")) {
    throw new Error("Node path cannot contain newline characters");
  }
  if (cliPath.includes("\n") || cliPath.includes("\r")) {
    throw new Error("CLI path cannot contain newline characters");
  }
  if (autootpHome && (autootpHome.includes("\n") || autootpHome.includes("\r"))) {
    throw new Error("AUTOOTP_HOME cannot contain newline characters");
  }

  const escapeSystemd = (s: string) => s.replace(/%/g, "%%").replace(/"/g, '\\"');

  const escapedNode = escapeSystemd(nodePath);
  const escapedCli = escapeSystemd(cliPath);

  let envLine = "";
  if (autootpHome && autootpHome.trim().length > 0) {
    envLine = `Environment="AUTOOTP_HOME=${escapeSystemd(autootpHome)}"\n`;
  }

  return `[Unit]
Description=AutoOTP background service

[Service]
ExecStart="${escapedNode}" "${escapedCli}" service
Restart=on-failure
RestartSec=5
RestartPreventExitStatus=78
NoNewPrivileges=yes
${envLine}
[Install]
WantedBy=default.target
`;
}

/**
 * Generates a macOS launchd agent plist.
 * // macOS launchd path: experimental, untested on a real Mac
 */
export function generateLaunchdPlist(options: {
  nodePath: string;
  cliPath: string;
  homeDir: string;
  autootpHome?: string;
}): string {
  const { nodePath, cliPath, homeDir, autootpHome } = options;
  const logDir = path.join(homeDir, "logs");
  const logFile = path.join(logDir, "service.log");

  // macOS launchd path: experimental, untested on a real Mac
  let envSection = "";
  if (autootpHome && autootpHome.trim().length > 0) {
    envSection = `  <key>EnvironmentVariables</key>
  <dict>
    <key>AUTOOTP_HOME</key>
    <string>${autootpHome}</string>
  </dict>
`;
  }

  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>org.autootp.service</string>
  <key>ProgramArguments</key>
  <array>
    <string>${nodePath}</string>
    <string>${cliPath}</string>
    <string>service</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>StandardOutPath</key>
  <string>${logFile}</string>
  <key>StandardErrorPath</key>
  <string>${logFile}</string>
${envSection}</dict>
</plist>
`;
}

/**
 * Enables AutoOTP auto-start service.
 */
export async function enableAction(context: AutoStartContext = {}): Promise<void> {
  const homeDir = context.homeDir ?? getHomeDir();
  const platform = context.platform ?? process.platform;
  const execFn = context.execFn ?? defaultExecFile;
  const nodePath = context.nodePath ?? process.execPath;
  const cliPath = context.cliPath ?? getCliDistPath();
  const autootpHome = context.autootpHome ?? process.env.AUTOOTP_HOME;

  if (platform === "win32") {
    console.error("Auto-start is not supported on Windows yet");
    if (context.exitImpl) {
      context.exitImpl(1);
      return;
    }
    process.exit(1);
  }

  // Prerequisites check
  const config = loadConfig(homeDir);
  if (!config.allowedOrigins || config.allowedOrigins.length === 0) {
    const msg = "No extension paired. Run: autootp pair <extensionId>";
    if (context.exitImpl) {
      console.error(msg);
      context.exitImpl(78);
      return;
    }
    throw new ConfigurationError(msg);
  }

  const store = new TokenStore(homeDir);
  const aliases = await store.list();
  if (aliases.length === 0) {
    const msg = "No accounts connected. Run: autootp login";
    if (context.exitImpl) {
      console.error(msg);
      context.exitImpl(78);
      return;
    }
    throw new ConfigurationError(msg);
  }

  if (platform === "linux") {
    const unitDir = context.unitDir ?? path.join(os.homedir(), ".config", "systemd", "user");
    fs.mkdirSync(unitDir, { recursive: true });
    const unitPath = path.join(unitDir, "autootp.service");

    const content = generateSystemdUnit({
      nodePath,
      cliPath,
      autootpHome
    });

    fs.writeFileSync(unitPath, content, "utf8");

    await execFn("systemctl", ["--user", "daemon-reload"]);
    await execFn("systemctl", ["--user", "enable", "--now", "autootp.service"]);

    console.log(`Service file written to: ${unitPath}`);
    console.log(`Node path recorded: ${nodePath}`);
    console.log("Note: After changing Node versions, you must run 'autootp enable' again.");
    return;
  }

  if (platform === "darwin") {
    // macOS launchd path: experimental, untested on a real Mac
    const launchAgentsDir = context.launchAgentsDir ?? path.join(os.homedir(), "Library", "LaunchAgents");
    fs.mkdirSync(launchAgentsDir, { recursive: true });
    const plistPath = path.join(launchAgentsDir, "org.autootp.service.plist");

    const logDir = path.join(homeDir, "logs");
    fs.mkdirSync(logDir, { recursive: true });

    const content = generateLaunchdPlist({
      nodePath,
      cliPath,
      homeDir,
      autootpHome
    });

    fs.writeFileSync(plistPath, content, "utf8");

    const uid = context.uid ?? (typeof process.getuid === "function" ? process.getuid() : 501);
    await execFn("launchctl", ["bootstrap", `gui/${uid}`, plistPath]);

    console.log(`Service plist written to: ${plistPath}`);
    console.log(`Node path recorded: ${nodePath}`);
    console.log("Note: After changing Node versions, you must run 'autootp enable' again.");
    console.log("Notice: macOS auto-start is experimental, untested on a real Mac.");
    return;
  }
}

/**
 * Disables and removes AutoOTP auto-start service.
 */
export async function disableAction(context: AutoStartContext = {}): Promise<void> {
  const platform = context.platform ?? process.platform;
  const execFn = context.execFn ?? defaultExecFile;

  if (platform === "win32") {
    console.error("Auto-start is not supported on Windows yet");
    if (context.exitImpl) {
      context.exitImpl(1);
      return;
    }
    process.exit(1);
  }

  if (platform === "linux") {
    const unitDir = context.unitDir ?? path.join(os.homedir(), ".config", "systemd", "user");
    const unitPath = path.join(unitDir, "autootp.service");
    try {
      await execFn("systemctl", ["--user", "stop", "autootp.service"]);
    } catch {}
    try {
      await execFn("systemctl", ["--user", "disable", "autootp.service"]);
    } catch {}
    if (fs.existsSync(unitPath)) {
      try {
        fs.unlinkSync(unitPath);
      } catch {}
    }
    try {
      await execFn("systemctl", ["--user", "daemon-reload"]);
    } catch {}
    try {
      await execFn("systemctl", ["--user", "reset-failed"]);
    } catch {}
    console.log("Auto-start service disabled and removed.");
    return;
  }

  if (platform === "darwin") {
    // macOS launchd path: experimental, untested on a real Mac
    const launchAgentsDir = context.launchAgentsDir ?? path.join(os.homedir(), "Library", "LaunchAgents");
    const plistPath = path.join(launchAgentsDir, "org.autootp.service.plist");
    const uid = context.uid ?? (typeof process.getuid === "function" ? process.getuid() : 501);
    try {
      await execFn("launchctl", ["bootout", `gui/${uid}`, plistPath]);
    } catch {}
    if (fs.existsSync(plistPath)) {
      try {
        fs.unlinkSync(plistPath);
      } catch {}
    }
    console.log("Auto-start service disabled and removed.");
    return;
  }
}

/**
 * Prints current status:
 * Service: running/stopped/not installed
 * Accounts: <n>
 * Paired extensions: <n>
 * Port <port>: listening/not listening
 */
export async function statusAction(context: AutoStartContext = {}): Promise<void> {
  const homeDir = context.homeDir ?? getHomeDir();
  const platform = context.platform ?? process.platform;
  const execFn = context.execFn ?? defaultExecFile;

  let serviceStatus = "not installed";

  if (platform === "linux") {
    const unitDir = context.unitDir ?? path.join(os.homedir(), ".config", "systemd", "user");
    const unitPath = path.join(unitDir, "autootp.service");
    if (fs.existsSync(unitPath)) {
      try {
        const { stdout } = await execFn("systemctl", ["--user", "is-active", "autootp.service"]);
        if (stdout.trim() === "active") {
          serviceStatus = "running";
        } else {
          serviceStatus = "stopped";
        }
      } catch (err: unknown) {
        const stdout = (err as { stdout?: string })?.stdout;
        if (typeof stdout === "string" && stdout.trim() === "active") {
          serviceStatus = "running";
        } else {
          serviceStatus = "stopped";
        }
      }
    } else {
      serviceStatus = "not installed";
    }
  } else if (platform === "darwin") {
    // macOS
    const launchAgentsDir = context.launchAgentsDir ?? path.join(os.homedir(), "Library", "LaunchAgents");
    const plistPath = path.join(launchAgentsDir, "org.autootp.service.plist");
    if (fs.existsSync(plistPath)) {
      try {
        const { stdout } = await execFn("launchctl", ["list", "org.autootp.service"]);
        serviceStatus = stdout.includes("PID") || stdout.length > 0 ? "running" : "stopped";
      } catch {
        serviceStatus = "stopped";
      }
    } else {
      serviceStatus = "not installed";
    }
  }

  const store = new TokenStore(homeDir);
  const aliases = await store.list();
  const accountsCount = aliases.length;

  const config = loadConfig(homeDir);
  const pairedCount = (config.allowedOrigins || []).length;

  const port = config.port || 47821;
  const isListening = context.checkPortListening
    ? await context.checkPortListening(port)
    : await checkPortListening(port);

  console.log(`Service: ${serviceStatus}`);
  console.log(`Accounts: ${accountsCount}`);
  console.log(`Paired extensions: ${pairedCount}`);
  console.log(`Port ${port}: ${isListening ? "listening" : "not listening"}`);
}
