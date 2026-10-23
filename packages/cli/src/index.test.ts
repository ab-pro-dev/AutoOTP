import fs from "node:fs";
import path from "node:path";
import { getEventListeners } from "node:events";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { TokenStore, loadConfig, saveConfig, HistoryStore } from "@autootp/shared";
import {
  validateAlias,
  validateExtensionId,
  formatAccountsTable,
  checkCredentialsPermissions,
  revokeToken,
  formatOtpNotification,
  formatHistoryTable
} from "./utils.js";
import {
  removeAction,
  loginAction,
  watchAction,
  pairAction,
  serviceAction,
  enableAction,
  disableAction,
  statusAction,
  configAction,
  configSetAction,
  historyAction,
  clearAction
} from "./commands.js";
import {
  generateSystemdUnit,
  generateLaunchdPlist,
  ExecFunction
} from "./autostart.js";
import { createProgram } from "./cli.js";

describe("CLI utilities and commands", () => {
  let tempDir: string;
  const originalHome = process.env.AUTOOTP_HOME;

  beforeEach(() => {
    const tmpBase = process.env.TMPDIR || process.env.TEMP || "/tmp";
    tempDir = fs.mkdtempSync(path.join(tmpBase, "autootp-cli-test-"));
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

  describe("Alias Validation", () => {
    it("accepts valid aliases (lowercase, digits, hyphens, 1-32 chars)", () => {
      const validCases = [
        "personal",
        "work",
        "work-email",
        "account-1",
        "123",
        "a",
        "a-b-c-d",
        "a".repeat(32)
      ];
      for (const alias of validCases) {
        expect(() => validateAlias(alias)).not.toThrow();
      }
    });

    it("rejects invalid aliases with descriptive errors", () => {
      const invalidCases = [
        "", // empty
        "Personal", // uppercase
        "MY-ACCOUNT", // uppercase
        "my account", // space
        "account_1", // underscore
        "account.1", // dot
        "acc@gmail", // special character
        "a".repeat(33) // too long
      ];
      for (const alias of invalidCases) {
        expect(() => validateAlias(alias)).toThrow(/Invalid alias/);
      }
    });
  });

  describe("Accounts Output Formatting", () => {
    it("returns empty-state message when no accounts connected", () => {
      const output = formatAccountsTable([]);
      expect(output).toBe("No accounts connected. Run: autootp login");
    });

    it("formats table with headers, divider and rows for connected accounts", () => {
      const accounts = [
        { alias: "personal", email: "personal@example.com", addedAt: 1700000000000 },
        { alias: "work", email: "work@company.com", addedAt: 1700050000000 }
      ];
      const output = formatAccountsTable(accounts);
      expect(output).toContain("ALIAS");
      expect(output).toContain("EMAIL");
      expect(output).toContain("ADDED");
      expect(output).toContain("personal");
      expect(output).toContain("personal@example.com");
      expect(output).toContain("work");
      expect(output).toContain("work@company.com");
    });
  });

  describe("Account Removal & Revocation", () => {
    it("removes account locally and attempts revoke", async () => {
      const store = new TokenStore(tempDir);
      await store.set("work", {
        refreshToken: "refresh-token-123",
        email: "work@example.com",
        addedAt: Date.now()
      });

      let revokeUrl = "";
      let revokeBody = "";
      const mockFetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        revokeUrl = input.toString();
        revokeBody = init?.body?.toString() ?? "";
        return new Response("", { status: 200 });
      };

      await removeAction("work", { homeDir: tempDir, fetchImpl: mockFetch as typeof fetch });

      expect(revokeUrl).toBe("https://oauth2.googleapis.com/revoke");
      expect(revokeBody).toContain("token=refresh-token-123");
      expect(await store.get("work")).toBeNull();
    });

    it("throws when removing a non-existent account", async () => {
      await expect(removeAction("nonexistent", { homeDir: tempDir })).rejects.toThrow(
        /Account "nonexistent" not found/
      );
    });

    it("revoke failure does not prevent local removal", async () => {
      const store = new TokenStore(tempDir);
      await store.set("backup", {
        refreshToken: "token-bad",
        email: "backup@example.com",
        addedAt: Date.now()
      });

      const failingFetch = async (): Promise<Response> => {
        return new Response("Bad Request", { status: 400 });
      };

      await removeAction("backup", { homeDir: tempDir, fetchImpl: failingFetch as typeof fetch });
      expect(await store.get("backup")).toBeNull();
    });
  });

  describe("Login Action Guards", () => {
    it("refuses login if the alias already exists", async () => {
      const store = new TokenStore(tempDir);
      await store.set("personal", {
        refreshToken: "r",
        email: "p@example.com",
        addedAt: Date.now()
      });

      await expect(loginAction("personal", { homeDir: tempDir })).rejects.toThrow(
        /Account "personal" already exists\. Run: autootp remove personal/
      );
    });
  });

  describe("Watch Action & Formatting", () => {
    it("formatOtpNotification formats single-line string with timestamp, sender, alias and code", () => {
      // Mock timestamp: 2026-01-01 12:30:45 local time
      const testDate = new Date(2026, 0, 1, 12, 30, 45);
      const formatted = formatOtpNotification({
        accountId: "work",
        sender: "GitHub",
        code: "948271",
        receivedAt: testDate.getTime(),
        maskCode: false
      });
      expect(formatted).toBe("[12:30:45] GitHub (work) -> 948271");
    });

    it("watchAction throws empty-state error when no accounts connected", async () => {
      await expect(watchAction({ homeDir: tempDir })).rejects.toThrow(
        "No accounts connected. Run: autootp login"
      );
    });

    it("watchAction runs watchers for connected accounts and terminates on signal", async () => {
      const store = new TokenStore(tempDir);
      await store.set("personal", {
        refreshToken: "ref-personal",
        email: "personal@example.com",
        addedAt: Date.now()
      });

      fs.writeFileSync(
        path.join(tempDir, "credentials.json"),
        JSON.stringify({
          installed: { client_id: "mock-id", client_secret: "mock-sec" }
        })
      );

      const controller = new AbortController();
      let watched = false;

      const mockFetch = async (input: RequestInfo | URL): Promise<Response> => {
        const urlStr = input.toString();
        if (urlStr.includes("oauth2.googleapis.com/token")) {
          return new Response(
            JSON.stringify({ access_token: "tok", expires_in: 3600 }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          );
        }
        if (urlStr.includes("/profile")) {
          return new Response(JSON.stringify({ historyId: "100" }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
        if (urlStr.includes("/messages")) {
          watched = true;
          controller.abort();
          return new Response(JSON.stringify({ messages: [] }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
        return new Response("Not found", { status: 404 });
      };

      await watchAction({
        homeDir: tempDir,
        fetchImpl: mockFetch as typeof fetch,
        signal: controller.signal,
        pollMs: 10
      });

      expect(watched).toBe(true);
    });

    it("abort listener limit: with N accounts watching, shared signal maintains at most N+2 listeners", async () => {
      const store = new TokenStore(tempDir);
      const N = 3;
      for (let i = 1; i <= N; i++) {
        await store.set(`acc-${i}`, {
          refreshToken: `ref-${i}`,
          email: `acc${i}@example.com`,
          addedAt: Date.now() + i
        });
      }

      fs.writeFileSync(
        path.join(tempDir, "credentials.json"),
        JSON.stringify({
          installed: { client_id: "mock-id", client_secret: "mock-sec" }
        })
      );

      const controller = new AbortController();
      let pollCount = 0;
      let maxListenersSeen = 0;

      const mockFetch = async (input: RequestInfo | URL): Promise<Response> => {
        const urlStr = input.toString();
        if (urlStr.includes("oauth2.googleapis.com/token")) {
          return new Response(
            JSON.stringify({ access_token: "tok", expires_in: 3600 }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          );
        }
        if (urlStr.includes("/profile")) {
          return new Response(JSON.stringify({ historyId: "100" }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
        if (urlStr.includes("/messages")) {
          return new Response(JSON.stringify({ messages: [] }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
        if (urlStr.includes("/history")) {
          pollCount++;
          const currentListeners = getEventListeners(controller.signal, "abort").length;
          if (currentListeners > maxListenersSeen) {
            maxListenersSeen = currentListeners;
          }
          expect(currentListeners).toBeLessThanOrEqual(N + 2);

          if (pollCount >= 15) {
            controller.abort();
          }
          return new Response(JSON.stringify({ history: [], historyId: "100" }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
        return new Response("Not found", { status: 404 });
      };

      await watchAction({
        homeDir: tempDir,
        fetchImpl: mockFetch as typeof fetch,
        signal: controller.signal,
        pollMs: 1
      });

      expect(pollCount).toBeGreaterThanOrEqual(10);
      expect(maxListenersSeen).toBeLessThanOrEqual(N + 2);
      expect(getEventListeners(controller.signal, "abort").length).toBeLessThanOrEqual(N + 2);
    });
  });

  describe("Pair Action & Extension Validation", () => {
    it("validates extension ID (32 chars in [a-p])", () => {
      const valid = "abcdefghijklmnopabcdefghijklmnop";
      expect(() => validateExtensionId(valid)).not.toThrow();

      expect(() => validateExtensionId("a".repeat(32))).not.toThrow();
      expect(() => validateExtensionId("p".repeat(32))).not.toThrow();

      // Bad cases
      expect(() => validateExtensionId("a".repeat(31))).toThrow(/Invalid extension ID/);
      expect(() => validateExtensionId("a".repeat(33))).toThrow(/Invalid extension ID/);
      expect(() => validateExtensionId("q".repeat(32))).toThrow(/Invalid extension ID/);
      expect(() => validateExtensionId("A".repeat(32))).toThrow(/Invalid extension ID/);
      expect(() => validateExtensionId("1".repeat(32))).toThrow(/Invalid extension ID/);
    });

    it("pair adds origins without duplicates and prints token", async () => {
      const extId1 = "abcdefghijklmnopabcdefghijklmnop";
      const extId2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

      const token1 = await pairAction(extId1, { homeDir: tempDir });
      expect(token1).toBeTruthy();
      expect(Buffer.from(token1, "base64url").length).toBe(32);

      let config = loadConfig(tempDir);
      expect(config.allowedOrigins).toEqual([`chrome-extension://${extId1}`]);

      // Call pair again with the same extension ID
      const token2 = await pairAction(extId1, { homeDir: tempDir });
      expect(token2).toBe(token1);

      config = loadConfig(tempDir);
      // No duplicate!
      expect(config.allowedOrigins).toEqual([`chrome-extension://${extId1}`]);

      // Call pair with a different extension ID
      await pairAction(extId2, { homeDir: tempDir });
      config = loadConfig(tempDir);
      expect(config.allowedOrigins).toEqual([
        `chrome-extension://${extId1}`,
        `chrome-extension://${extId2}`
      ]);
    });

    it("createProgram runs pair command successfully", async () => {
      const extId = "abcdefghijklmnopabcdefghijklmnop";
      const program = createProgram({ homeDir: tempDir });
      await program.parseAsync(["node", "autootp", "pair", extId]);

      const config = loadConfig(tempDir);
      expect(config.allowedOrigins).toContain(`chrome-extension://${extId}`);
    });

    it("createProgram runs service --no-watch and terminates cleanly on signal", async () => {
      const extId = "abcdefghijklmnopabcdefghijklmnop";
      await pairAction(extId, { homeDir: tempDir });
      saveConfig(
        {
          allowedOrigins: [`chrome-extension://${extId}`],
          port: 49123
        },
        tempDir
      );

      const controller = new AbortController();
      const program = createProgram({
        homeDir: tempDir,
        signal: controller.signal
      });

      const runPromise = program.parseAsync([
        "node",
        "autootp",
        "service",
        "--no-watch"
      ]);

      // Allow service to initialize and then abort
      await new Promise((resolve) => setTimeout(resolve, 50));
      controller.abort();

      await expect(runPromise).resolves.toBeDefined();
    });
  });

  describe("Non-TTY Masking and Background-Safe Output", () => {
    it("masks code with asterisks in non-TTY output and proves no digits appear", () => {
      const otp = {
        accountId: "personal",
        sender: "GitHub",
        code: "892147",
        receivedAt: 1700000000000
      };

      // Explicitly test non-TTY / masked mode
      const maskedLine = formatOtpNotification({ ...otp, maskCode: true });
      expect(maskedLine).toContain("GitHub (personal) -> ******");
      const arrowParts = maskedLine.split("->");
      const codePart = arrowParts[1].trim();
      expect(codePart).toBe("******");
      expect(codePart.length).toBe(otp.code.length);
      // Prove no digits of the code appear in non-TTY output
      expect(/\d/.test(codePart)).toBe(false);

      // Verify TTY output retains the full unmasked code
      const unmaskedLine = formatOtpNotification({ ...otp, maskCode: false });
      expect(unmaskedLine).toContain("GitHub (personal) -> 892147");
      expect(unmaskedLine.split("->")[1].trim()).toBe("892147");
    });

    it("respects process.stdout.isTTY boolean", () => {
      const origIsTTY = process.stdout.isTTY;
      try {
        process.stdout.isTTY = false;
        const lineNonTTY = formatOtpNotification({
          accountId: "work",
          sender: "Google",
          code: "123456"
        });
        expect(lineNonTTY).toContain("Google (work) -> ******");
        expect(/\d/.test(lineNonTTY.split("->")[1])).toBe(false);

        process.stdout.isTTY = true;
        const lineTTY = formatOtpNotification({
          accountId: "work",
          sender: "Google",
          code: "123456"
        });
        expect(lineTTY).toContain("Google (work) -> 123456");
      } finally {
        process.stdout.isTTY = origIsTTY;
      }
    });
  });

  describe("Exit Code 78 for Service Configuration Problems", () => {
    it("exits with 78 when no extension is paired", async () => {
      let exitCode: number | undefined;
      await serviceAction({
        homeDir: tempDir,
        noWatch: true,
        exitImpl: (code) => {
          exitCode = code;
        }
      });
      expect(exitCode).toBe(78);
    });

    it("exits with 78 when no accounts are connected", async () => {
      await pairAction("abcdefghijklmnopabcdefghijklmnop", { homeDir: tempDir });
      let exitCode: number | undefined;
      await serviceAction({
        homeDir: tempDir,
        noWatch: false,
        exitImpl: (code) => {
          exitCode = code;
        }
      });
      expect(exitCode).toBe(78);
    });
  });

  describe("Auto-Start Enable and Disable", () => {
    it("generates systemd unit with proper quoting, % escaping, and no secrets", () => {
      const unit = generateSystemdUnit({
        nodePath: "/usr/local/bin/%node-20%",
        cliPath: "/opt/autootp/dist/index.js",
        autootpHome: "/custom/%autootp%_home"
      });

      // Both paths must be double-quoted in ExecStart
      expect(unit).toContain('ExecStart="/usr/local/bin/%%node-20%%" "/opt/autootp/dist/index.js" service');
      // Every % must be escaped as %%
      expect(unit).toContain('Environment="AUTOOTP_HOME=/custom/%%autootp%%_home"');
      // Required systemd directives
      expect(unit).toContain("Restart=on-failure");
      expect(unit).toContain("RestartSec=5");
      expect(unit).toContain("RestartPreventExitStatus=78");
      expect(unit).toContain("NoNewPrivileges=yes");
      expect(unit).toContain("[Install]\nWantedBy=default.target");
      // No secrets of any kind
      expect(unit).not.toMatch(/token|secret|password|bearer|key/i);
    });

    it("omits Environment line from systemd unit when AUTOOTP_HOME is not set", () => {
      const unit = generateSystemdUnit({
        nodePath: "/usr/bin/node",
        cliPath: "/opt/autootp/dist/index.js"
      });

      expect(unit).not.toContain("Environment=");
    });

    it("refuses paths containing newline characters in systemd unit", () => {
      expect(() =>
        generateSystemdUnit({
          nodePath: "/usr/bin/node\nrm -rf /",
          cliPath: "/opt/autootp/dist/index.js"
        })
      ).toThrow(/newline/i);

      expect(() =>
        generateSystemdUnit({
          nodePath: "/usr/bin/node",
          cliPath: "/opt/autootp/dist/index.js\r"
        })
      ).toThrow(/newline/i);
    });

    it("generates macOS launchd plist with required tags and log paths", () => {
      const plist = generateLaunchdPlist({
        nodePath: "/usr/local/bin/node",
        cliPath: "/Users/test/autootp/dist/index.js",
        homeDir: "/Users/test/.autootp"
      });

      expect(plist).toContain("<key>Label</key>\n  <string>org.autootp.service</string>");
      expect(plist).toContain("<key>RunAtLoad</key>\n  <true/>");
      expect(plist).toContain("<key>KeepAlive</key>\n  <dict>\n    <key>SuccessfulExit</key>\n    <false/>\n  </dict>");
      expect(plist).toContain("<string>/Users/test/.autootp/logs/service.log</string>");
      expect(plist).toContain("<string>/usr/local/bin/node</string>");
      expect(plist).toContain("<string>/Users/test/autootp/dist/index.js</string>");
      expect(plist).toContain("<string>service</string>");
    });

    it("refuses enable when prerequisites are missing (no extension paired)", async () => {
      const executedCommands: Array<{ file: string; args: string[] }> = [];
      const mockExec: ExecFunction = async (file, args) => {
        executedCommands.push({ file, args });
        return { stdout: "", stderr: "" };
      };

      let exitCode: number | undefined;
      await enableAction({
        homeDir: tempDir,
        platform: "linux",
        execFn: mockExec,
        exitImpl: (code) => {
          exitCode = code;
        }
      });

      expect(exitCode).toBe(78);
      // Nothing should have been executed or installed
      expect(executedCommands).toHaveLength(0);
    });

    it("refuses enable when prerequisites are missing (no accounts connected)", async () => {
      await pairAction("abcdefghijklmnopabcdefghijklmnop", { homeDir: tempDir });

      const executedCommands: Array<{ file: string; args: string[] }> = [];
      const mockExec: ExecFunction = async (file, args) => {
        executedCommands.push({ file, args });
        return { stdout: "", stderr: "" };
      };

      let exitCode: number | undefined;
      await enableAction({
        homeDir: tempDir,
        platform: "linux",
        execFn: mockExec,
        exitImpl: (code) => {
          exitCode = code;
        }
      });

      expect(exitCode).toBe(78);
      expect(executedCommands).toHaveLength(0);
    });

    it("prints message and exits 1 on Windows for enable and disable", async () => {
      let exitCode: number | undefined;
      await enableAction({
        homeDir: tempDir,
        platform: "win32",
        exitImpl: (code) => {
          exitCode = code;
        }
      });
      expect(exitCode).toBe(1);

      let disableExitCode: number | undefined;
      await disableAction({
        homeDir: tempDir,
        platform: "win32",
        exitImpl: (code) => {
          disableExitCode = code;
        }
      });
      expect(disableExitCode).toBe(1);
    });

    it("enables systemd service on Linux with mock exec", async () => {
      await pairAction("abcdefghijklmnopabcdefghijklmnop", { homeDir: tempDir });
      const store = new TokenStore(tempDir);
      await store.set("personal", {
        refreshToken: "mock-token",
        email: "user@example.com",
        addedAt: Date.now()
      });

      const executedCommands: Array<{ file: string; args: string[] }> = [];
      const mockExec: ExecFunction = async (file, args) => {
        executedCommands.push({ file, args });
        return { stdout: "", stderr: "" };
      };

      await enableAction({
        homeDir: tempDir,
        unitDir: path.join(tempDir, "systemd"),
        platform: "linux",
        execFn: mockExec,
        nodePath: "/usr/bin/node",
        cliPath: "/opt/autootp/dist/index.js"
      });

      expect(executedCommands).toEqual([
        { file: "systemctl", args: ["--user", "daemon-reload"] },
        { file: "systemctl", args: ["--user", "enable", "--now", "autootp.service"] }
      ]);
    });

    it("disables systemd service cleanly and is safe when nothing is installed", async () => {
      const executedCommands: Array<{ file: string; args: string[] }> = [];
      const mockExec: ExecFunction = async (file, args) => {
        executedCommands.push({ file, args });
        return { stdout: "", stderr: "" };
      };

      await disableAction({
        unitDir: path.join(tempDir, "systemd"),
        platform: "linux",
        execFn: mockExec
      });

      expect(executedCommands).toEqual([
        { file: "systemctl", args: ["--user", "stop", "autootp.service"] },
        { file: "systemctl", args: ["--user", "disable", "autootp.service"] },
        { file: "systemctl", args: ["--user", "daemon-reload"] },
        { file: "systemctl", args: ["--user", "reset-failed"] }
      ]);
    });
  });

  describe("Status Command", () => {
    it("prints four lines with service, accounts, extensions, and port status", async () => {
      await pairAction("abcdefghijklmnopabcdefghijklmnop", { homeDir: tempDir });
      const store = new TokenStore(tempDir);
      await store.set("work", {
        refreshToken: "mock-token",
        email: "work@example.com",
        addedAt: Date.now()
      });

      const lines: string[] = [];
      const origLog = console.log;
      console.log = (msg: string) => lines.push(msg);

      try {
        await statusAction({
          homeDir: tempDir,
          platform: "linux",
          execFn: async () => ({ stdout: "active\n", stderr: "" }),
          checkPortListening: async () => true
        });
      } finally {
        console.log = origLog;
      }

      expect(lines).toHaveLength(4);
      expect(lines[0]).toMatch(/^Service: (running|stopped|not installed)$/);
      expect(lines[1]).toBe("Accounts: 1");
      expect(lines[2]).toBe("Paired extensions: 1");
      expect(lines[3]).toBe("Port 47821: listening");

      // Verify no tokens leaked
      for (const line of lines) {
        expect(line).not.toMatch(/mock-token/);
        expect(line).not.toMatch(/token/i);
      }
    });

    it("reports stopped and not listening when inactive", async () => {
      const lines: string[] = [];
      const origLog = console.log;
      console.log = (msg: string) => lines.push(msg);

      try {
        await statusAction({
          homeDir: tempDir,
          platform: "linux",
          execFn: async () => {
            const err = new Error("inactive");
            (err as any).stdout = "inactive\n";
            throw err;
          },
          checkPortListening: async () => false
        });
      } finally {
        console.log = origLog;
      }

      expect(lines).toHaveLength(4);
      expect(lines[0]).toMatch(/^Service: (stopped|not installed)$/);
      expect(lines[1]).toBe("Accounts: 0");
      expect(lines[2]).toBe("Paired extensions: 0");
      expect(lines[3]).toBe("Port 47821: not listening");
    });
  });

  describe("Config Command", () => {
    it("prints current historyRetention", async () => {
      const lines: string[] = [];
      const origLog = console.log;
      console.log = (msg: string) => lines.push(msg);

      try {
        await configAction({ homeDir: tempDir });
      } finally {
        console.log = origLog;
      }

      expect(lines).toContain("historyRetention: 5m");
      // Must not expose port, pollMs, or other keys
      expect(lines.some((l) => l.includes("port"))).toBe(false);
      expect(lines.some((l) => l.includes("pollMs"))).toBe(false);
    });

    it("sets valid historyRetention value", async () => {
      await configSetAction("historyRetention", "30m", { homeDir: tempDir });
      const config = loadConfig(tempDir);
      expect(config.historyRetention).toBe("30m");

      await configSetAction("historyRetention", "off", { homeDir: tempDir });
      expect(loadConfig(tempDir).historyRetention).toBe("off");

      await configSetAction("historyRetention", "1h", { homeDir: tempDir });
      expect(loadConfig(tempDir).historyRetention).toBe("1h");
    });

    it("rejects unknown keys and exits 1", async () => {
      let exitCode: number | undefined;
      const errors: string[] = [];
      const origErr = console.error;
      console.error = (msg: string) => errors.push(msg);

      try {
        await configSetAction("port", "8080", {
          homeDir: tempDir,
          exitImpl: (code) => {
            exitCode = code;
          }
        });
      } finally {
        console.error = origErr;
      }

      expect(exitCode).toBe(1);
      expect(errors[0]).toMatch(/Only "historyRetention" and "notifications" can be configured/);
    });

    it("rejects invalid historyRetention values and exits 1", async () => {
      let exitCode: number | undefined;
      const errors: string[] = [];
      const origErr = console.error;
      console.error = (msg: string) => errors.push(msg);

      try {
        await configSetAction("historyRetention", "2h", {
          homeDir: tempDir,
          exitImpl: (code) => {
            exitCode = code;
          }
        });
      } finally {
        console.error = origErr;
      }

      expect(exitCode).toBe(1);
      expect(errors[0]).toMatch(/Valid values: off, 5m, 30m, 1h/);
    });

    it("sets valid notifications value and validates in config", async () => {
      await configSetAction("notifications", "hidden", { homeDir: tempDir });
      expect(loadConfig(tempDir).notifications).toBe("hidden");

      await configSetAction("notifications", "off", { homeDir: tempDir });
      expect(loadConfig(tempDir).notifications).toBe("off");

      await configSetAction("notifications", "code", { homeDir: tempDir });
      expect(loadConfig(tempDir).notifications).toBe("code");
    });

    it("rejects invalid notifications values and exits 1", async () => {
      let exitCode: number | undefined;
      const errors: string[] = [];
      const origErr = console.error;
      console.error = (msg: string) => errors.push(msg);

      try {
        await configSetAction("notifications", "loud", {
          homeDir: tempDir,
          exitImpl: (code) => {
            exitCode = code;
          }
        });
      } finally {
        console.error = origErr;
      }

      expect(exitCode).toBe(1);
      expect(errors[0]).toMatch(/Valid values: off, hidden, code/);
    });
  });

  describe("History and Clear Commands", () => {
    it("prints 'No history.' when empty", async () => {
      const lines: string[] = [];
      const origLog = console.log;
      console.log = (msg: string) => lines.push(msg);

      try {
        await historyAction({ homeDir: tempDir });
      } finally {
        console.log = origLog;
      }

      expect(lines).toEqual(["No history."]);
    });

    it("prints formatted history table newest first", async () => {
      const store = new HistoryStore(tempDir);
      const now = Date.now();
      store.add({
        sender: "GitHub",
        senderDomain: "github.com",
        alias: "personal",
        code: "948210",
        receivedAt: now - 10000
      });
      store.add({
        sender: "AWS",
        senderDomain: "amazon.com",
        alias: "work",
        code: "554433",
        receivedAt: now - 1000
      });
      store.close();

      const lines: string[] = [];
      const origLog = console.log;
      console.log = (msg: string) => lines.push(msg);

      try {
        await historyAction({ homeDir: tempDir });
      } finally {
        console.log = origLog;
      }

      expect(lines.length).toBeGreaterThan(0);
      const output = lines.join("\n");
      expect(output).toContain("AGE");
      expect(output).toContain("SENDER");
      expect(output).toContain("ALIAS");
      expect(output).toContain("CODE");
      expect(output).toContain("AWS");
      expect(output).toContain("GitHub");
      expect(output).toContain("554433");
      expect(output).toContain("948210");
    });

    it("clears all history and reports row count", async () => {
      const store = new HistoryStore(tempDir);
      store.add({
        sender: "GitHub",
        senderDomain: "github.com",
        alias: "personal",
        code: "948210",
        receivedAt: Date.now()
      });
      store.add({
        sender: "Google",
        senderDomain: "google.com",
        alias: "personal",
        code: "123456",
        receivedAt: Date.now()
      });
      store.close();

      const lines: string[] = [];
      const origLog = console.log;
      console.log = (msg: string) => lines.push(msg);

      try {
        await clearAction({ homeDir: tempDir });
      } finally {
        console.log = origLog;
      }

      expect(lines).toHaveLength(1);
      expect(lines[0]).toMatch(/Cleared 2 rows from history/);

      // Verify history is empty
      const storeAfter = new HistoryStore(tempDir);
      expect(storeAfter.list()).toHaveLength(0);
      storeAfter.close();
    });
  });
});



