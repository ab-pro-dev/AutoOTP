import fs from "node:fs";
import path from "node:path";
import { getEventListeners } from "node:events";
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { TokenStore, loadConfig, saveConfig, HistoryStore, writeStatus, VERSION } from "@autootp/shared";
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
  clearAction,
  doctorAction,
  auditAction
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
    it("formatOtpNotification formats single-line string with timestamp, sender, alias, code, and verified marker", () => {
      // Mock timestamp: 2026-01-01 12:30:45 local time
      const testDate = new Date(2026, 0, 1, 12, 30, 45);
      const formattedUnverified = formatOtpNotification({
        accountId: "work",
        sender: "GitHub",
        code: "948271",
        receivedAt: testDate.getTime(),
        maskCode: false,
        senderVerified: false
      });
      expect(formattedUnverified).toBe("[12:30:45] GitHub (work) -> 948271 [unverified]");

      const formattedVerified = formatOtpNotification({
        accountId: "work",
        sender: "GitHub",
        code: "948271",
        receivedAt: testDate.getTime(),
        maskCode: false,
        senderVerified: true
      });
      expect(formattedVerified).toBe("[12:30:45] GitHub (work) -> 948271 [verified]");
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
      expect(maskedLine).toContain("[unverified]");
      const arrowParts = maskedLine.split("->");
      const afterArrow = arrowParts[1].trim();
      const codePart = afterArrow.split(/\s+/)[0];
      expect(codePart).toBe("******");
      expect(codePart.length).toBe(otp.code.length);
      // Prove no digits of the code appear in non-TTY output
      expect(/\d/.test(codePart)).toBe(false);

      // Verify TTY output retains the full unmasked code with verified marker
      const unmaskedLine = formatOtpNotification({ ...otp, maskCode: false, senderVerified: true });
      expect(unmaskedLine).toContain("GitHub (personal) -> 892147 [verified]");
      expect(unmaskedLine.split("->")[1].trim().split(/\s+/)[0]).toBe("892147");
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
        expect(lineNonTTY).toContain("[unverified]");
        expect(/\d/.test(lineNonTTY.split("->")[1].split(/\s+/)[0])).toBe(false);

        process.stdout.isTTY = true;
        const lineTTY = formatOtpNotification({
          accountId: "work",
          sender: "Google",
          code: "123456",
          senderVerified: true
        });
        expect(lineTTY).toContain("Google (work) -> 123456 [verified]");
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
    it("prints status with unknown Browser and Accounts when status file is missing", async () => {
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

      expect(lines).toHaveLength(5);
      expect(lines[0]).toBe("Service: running");
      expect(lines[1]).toBe("Browser: unknown (service not running?)");
      expect(lines[2]).toBe("Accounts: unknown (service not running?)");
      expect(lines[3]).toBe("Latest OTP: none");
      expect(lines[4]).toBe("Port 47821: listening");
    });

    it("prints status with unknown Browser and Accounts when status file is stale (> 90s)", async () => {
      const now = 1700000000000;
      writeStatus(
        {
          v: 1,
          pid: 1234,
          version: "0.1.0",
          startedAt: now - 200000,
          updatedAt: now - 95000, // 95s ago > 90s
          port: 47821,
          authedClients: 1,
          accounts: { personal: "ok" },
          lastOtp: null
        },
        tempDir
      );

      const lines: string[] = [];
      const origLog = console.log;
      console.log = (msg: string) => lines.push(msg);

      try {
        await statusAction({
          homeDir: tempDir,
          now: () => now,
          platform: "linux",
          execFn: async () => ({ stdout: "active\n", stderr: "" }),
          checkPortListening: async () => true
        });
      } finally {
        console.log = origLog;
      }

      expect(lines).toContain("Browser: unknown (service not running?)");
      expect(lines).toContain("Accounts: unknown (service not running?)");
      expect(lines).toContain("Latest OTP: none");
    });

    it("prints full status with connected browser, account states, and latest OTP when fresh", async () => {
      const now = 1700000000000;
      writeStatus(
        {
          v: 1,
          pid: 1234,
          version: "0.1.0",
          startedAt: now - 60000,
          updatedAt: now - 5000, // 5s ago
          port: 47821,
          authedClients: 2,
          accounts: {
            personal: "expired",
            work: "ok"
          },
          lastOtp: {
            sender: "GitHub",
            senderDomain: "github.com",
            at: now - 8000
          }
        },
        tempDir
      );

      const lines: string[] = [];
      const origLog = console.log;
      console.log = (msg: string) => lines.push(msg);

      try {
        await statusAction({
          homeDir: tempDir,
          now: () => now,
          platform: "linux",
          execFn: async () => ({ stdout: "active\n", stderr: "" }),
          checkPortListening: async () => true
        });
      } finally {
        console.log = origLog;
      }

      expect(lines[0]).toBe("Service: running");
      expect(lines[1]).toBe("Browser: connected (2)");
      expect(lines[2]).toBe("Accounts:");
      expect(lines[3]).toBe("  personal: run: autootp login personal");
      expect(lines[4]).toBe("  work: ok");
      expect(lines[5]).toBe("Latest OTP: GitHub 8s ago");
      expect(lines[6]).toBe("Port 47821: listening");
    });

    it("reports stopped and not listening when service is not running", async () => {
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

      expect(lines[0]).toBe("Service: stopped");
      expect(lines[1]).toBe("Browser: unknown (service not running?)");
      expect(lines[2]).toBe("Accounts: unknown (service not running?)");
      expect(lines[3]).toBe("Latest OTP: none");
      expect(lines[4]).toBe("Port 47821: not listening");
    });

    it("reports Browser: not connected when fresh status has authedClients = 0", async () => {
      const now = 1700000000000;
      writeStatus(
        {
          v: 1,
          pid: 1234,
          version: "0.1.0",
          startedAt: now - 30000,
          updatedAt: now - 2000,
          port: 47821,
          authedClients: 0,
          accounts: {},
          lastOtp: null
        },
        tempDir
      );

      const lines: string[] = [];
      const origLog = console.log;
      console.log = (msg: string) => lines.push(msg);

      try {
        await statusAction({
          homeDir: tempDir,
          now: () => now,
          platform: "linux",
          execFn: async () => ({ stdout: "active\n", stderr: "" }),
          checkPortListening: async () => true
        });
      } finally {
        console.log = origLog;
      }

      expect(lines).toContain("Browser: not connected");
      expect(lines).toContain("Accounts: none");
      expect(lines).toContain("Latest OTP: none");
    });

    it("never leaks secret tokens, pair tokens, or codes in status output", async () => {
      const now = 1700000000000;
      const secretToken = "super-secret-refresh-token-xyz";
      const store = new TokenStore(tempDir);
      await store.set("personal", {
        refreshToken: secretToken,
        email: "user@example.com",
        addedAt: now
      });
      const pairToken = await pairAction("abcdefghijklmnopabcdefghijklmnop", { homeDir: tempDir });

      writeStatus(
        {
          v: 1,
          pid: 1234,
          version: "0.1.0",
          startedAt: now - 10000,
          updatedAt: now - 1000,
          port: 47821,
          authedClients: 1,
          accounts: { personal: "ok" },
          lastOtp: {
            sender: "GitHub",
            senderDomain: "github.com",
            at: now - 5000
          }
        },
        tempDir
      );

      const lines: string[] = [];
      const origLog = console.log;
      console.log = (msg: string) => lines.push(msg);

      try {
        await statusAction({
          homeDir: tempDir,
          now: () => now,
          platform: "linux",
          execFn: async () => ({ stdout: "active\n", stderr: "" }),
          checkPortListening: async () => true
        });
      } finally {
        console.log = origLog;
      }

      const allOutput = lines.join("\n");
      expect(allOutput).not.toContain(secretToken);
      expect(allOutput).not.toContain(pairToken);
      expect(allOutput).not.toMatch(/\b\d{6,8}\b/);
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

  describe("Doctor Command", () => {
    async function setupPassingEnv(homeDir: string) {
      const now = Date.now();
      // 1. credentials.json with mode 600
      const credPath = path.join(homeDir, "credentials.json");
      fs.writeFileSync(
        credPath,
        JSON.stringify({
          installed: {
            client_id: "test-client-id",
            client_secret: "test-client-secret",
            auth_uri: "https://accounts.google.com/o/oauth2/auth",
            token_uri: "https://oauth2.googleapis.com/token"
          }
        }),
        { mode: 0o600 }
      );
      fs.chmodSync(credPath, 0o600);

      // 2. config.json with allowedOrigins
      saveConfig(
        {
          allowedOrigins: ["chrome-extension://abcdefghijklmnopabcdefghijklmnop"],
          port: 47821
        },
        homeDir
      );

      // 3. key and tokens.enc in TokenStore
      const store = new TokenStore(homeDir);
      await store.set("personal", {
        refreshToken: "valid-mock-refresh-token",
        email: "user@example.com",
        addedAt: now
      });

      // 4. status.json fresh with authedClients = 1
      writeStatus(
        {
          v: 1,
          pid: 1234,
          version: VERSION,
          startedAt: now - 30000,
          updatedAt: now - 1000,
          port: 47821,
          authedClients: 1,
          accounts: { personal: "ok" },
          lastOtp: null
        },
        homeDir
      );

      // 5. systemd unit
      const unitDir = path.join(homeDir, "systemd");
      fs.mkdirSync(unitDir, { recursive: true });
      fs.writeFileSync(path.join(unitDir, "autootp.service"), "[Unit]\nDescription=AutoOTP\n");

      return {
        unitDir,
        mockExec: async (file: string, args: string[]) => {
          if (file === "systemctl" && args.includes("is-active")) {
            return { stdout: "active\n", stderr: "" };
          }
          if (file === "which" && args.includes("notify-send")) {
            return { stdout: "/usr/bin/notify-send\n", stderr: "" };
          }
          return { stdout: "", stderr: "" };
        },
        mockFetch: async () => {
          return new Response(
            JSON.stringify({
              access_token: "new-access-token",
              expires_in: 3600,
              token_type: "Bearer"
            }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          );
        }
      };
    }

    it("passes all checks when environment is fully configured and exits 0", async () => {
      const { unitDir, mockExec, mockFetch } = await setupPassingEnv(tempDir);
      let exitCode: number | undefined;
      const lines: string[] = [];
      const origLog = console.log;
      console.log = (msg: string) => lines.push(msg);

      try {
        await doctorAction({
          homeDir: tempDir,
          unitDir,
          platform: "linux",
          nodeVersion: "22.14.0",
          execFn: mockExec,
          fetchImpl: mockFetch,
          checkPortListening: async () => true,
          exitImpl: (code) => {
            exitCode = code;
          }
        });
      } finally {
        console.log = origLog;
      }

      expect(exitCode).toBeUndefined();
      expect(lines.some((l) => l.startsWith("FAIL"))).toBe(false);
      expect(lines.some((l) => l.includes("Node.js version 22.14.0"))).toBe(true);
      expect(lines.some((l) => l.includes("config.json is valid"))).toBe(true);
      expect(lines.some((l) => l.includes("credentials.json exists with mode 600"))).toBe(true);
      expect(lines.some((l) => l.includes("key, tokens.enc and history.db have mode 600"))).toBe(true);
      expect(lines.some((l) => l.includes('Account "personal" refresh token is valid'))).toBe(true);
      expect(lines.some((l) => l.includes("1 paired extension(s)"))).toBe(true);
      expect(lines.some((l) => l.includes("Service is installed and running"))).toBe(true);
      expect(lines.some((l) => l.includes("Port 47821 is listening"))).toBe(true);
      expect(lines.some((l) => l.includes("Status file is fresh"))).toBe(true);
      expect(lines.some((l) => l.includes("Browser extension connected (1)"))).toBe(true);
      expect(lines.some((l) => l.includes("Notification tool available (notify-send)"))).toBe(true);
      expect(lines[lines.length - 1]).toBe(`Version: ${VERSION}`);
    });

    it("fails when Node.js version is older than 22.13 and exits 1", async () => {
      const { unitDir, mockExec, mockFetch } = await setupPassingEnv(tempDir);
      let exitCode: number | undefined;
      const lines: string[] = [];
      const origLog = console.log;
      console.log = (msg: string) => lines.push(msg);

      try {
        await doctorAction({
          homeDir: tempDir,
          unitDir,
          platform: "linux",
          nodeVersion: "20.11.0",
          execFn: mockExec,
          fetchImpl: mockFetch,
          checkPortListening: async () => true,
          exitImpl: (code) => {
            exitCode = code;
          }
        });
      } finally {
        console.log = origLog;
      }

      expect(exitCode).toBe(1);
      expect(lines.some((l) => l.startsWith("FAIL Node.js version 20.11.0 (requires >= 22.13)"))).toBe(true);
    });

    it("accepts Node.js versions >= 22.13 with or without leading v", async () => {
      const { unitDir, mockExec, mockFetch } = await setupPassingEnv(tempDir);
      let exitCode: number | undefined;
      const lines: string[] = [];
      const origLog = console.log;
      console.log = (msg: string) => lines.push(msg);

      try {
        await doctorAction({
          homeDir: tempDir,
          unitDir,
          platform: "linux",
          nodeVersion: "v22.13.0",
          execFn: mockExec,
          fetchImpl: mockFetch,
          checkPortListening: async () => true,
          exitImpl: (code) => {
            exitCode = code;
          }
        });
      } finally {
        console.log = origLog;
      }

      expect(exitCode).toBeUndefined();
      expect(lines.some((l) => l.startsWith("OK Node.js version v22.13.0"))).toBe(true);
    });

    it("fails when credentials.json is missing or has incorrect mode", async () => {
      const { unitDir, mockExec, mockFetch } = await setupPassingEnv(tempDir);
      // Remove credentials.json
      fs.unlinkSync(path.join(tempDir, "credentials.json"));

      let exitCode: number | undefined;
      const lines: string[] = [];
      const origLog = console.log;
      console.log = (msg: string) => lines.push(msg);

      try {
        await doctorAction({
          homeDir: tempDir,
          unitDir,
          platform: "linux",
          nodeVersion: "22.14.0",
          execFn: mockExec,
          fetchImpl: mockFetch,
          checkPortListening: async () => true,
          exitImpl: (code) => {
            exitCode = code;
          }
        });
      } finally {
        console.log = origLog;
      }

      expect(exitCode).toBe(1);
      expect(lines.some((l) => l.includes("credentials.json missing"))).toBe(true);
    });

    it("fails when key, tokens.enc or history.db have insecure permissions", async () => {
      const { unitDir, mockExec, mockFetch } = await setupPassingEnv(tempDir);
      const keyPath = path.join(tempDir, "key");
      fs.chmodSync(keyPath, 0o644);

      let exitCode: number | undefined;
      const lines: string[] = [];
      const origLog = console.log;
      console.log = (msg: string) => lines.push(msg);

      try {
        await doctorAction({
          homeDir: tempDir,
          unitDir,
          platform: "linux",
          nodeVersion: "22.14.0",
          execFn: mockExec,
          fetchImpl: mockFetch,
          checkPortListening: async () => true,
          exitImpl: (code) => {
            exitCode = code;
          }
        });
      } finally {
        console.log = origLog;
      }

      expect(exitCode).toBe(1);
      expect(lines.some((l) => l.includes("Permissions incorrect for: key (0o644), expected 0o600"))).toBe(true);
    });

    it("fails when no accounts are connected", async () => {
      const { unitDir, mockExec, mockFetch } = await setupPassingEnv(tempDir);
      // Remove token store
      const store = new TokenStore(tempDir);
      await store.remove("personal");

      let exitCode: number | undefined;
      const lines: string[] = [];
      const origLog = console.log;
      console.log = (msg: string) => lines.push(msg);

      try {
        await doctorAction({
          homeDir: tempDir,
          unitDir,
          platform: "linux",
          nodeVersion: "22.14.0",
          execFn: mockExec,
          fetchImpl: mockFetch,
          checkPortListening: async () => true,
          exitImpl: (code) => {
            exitCode = code;
          }
        });
      } finally {
        console.log = origLog;
      }

      expect(exitCode).toBe(1);
      expect(lines.some((l) => l.includes("No accounts connected. Run: autootp login"))).toBe(true);
    });

    it("fails with login hint when account refresh returns ReauthRequiredError", async () => {
      const { unitDir, mockExec } = await setupPassingEnv(tempDir);

      const expiredFetch = async () => {
        return new Response(
          JSON.stringify({ error: "invalid_grant", error_description: "Token has been expired or revoked." }),
          { status: 400, headers: { "Content-Type": "application/json" } }
        );
      };

      let exitCode: number | undefined;
      const lines: string[] = [];
      const origLog = console.log;
      console.log = (msg: string) => lines.push(msg);

      try {
        await doctorAction({
          homeDir: tempDir,
          unitDir,
          platform: "linux",
          nodeVersion: "22.14.0",
          execFn: mockExec,
          fetchImpl: expiredFetch,
          checkPortListening: async () => true,
          exitImpl: (code) => {
            exitCode = code;
          }
        });
      } finally {
        console.log = origLog;
      }

      expect(exitCode).toBe(1);
      expect(lines.some((l) => l.includes('FAIL Account "personal" expired: run autootp login personal'))).toBe(true);
    });

    it("warns and does not fail on account refresh network error", async () => {
      const { unitDir, mockExec } = await setupPassingEnv(tempDir);

      const networkErrorFetch = async () => {
        throw new TypeError("fetch failed: ENOTFOUND oauth2.googleapis.com");
      };

      let exitCode: number | undefined;
      const lines: string[] = [];
      const origLog = console.log;
      console.log = (msg: string) => lines.push(msg);

      try {
        await doctorAction({
          homeDir: tempDir,
          unitDir,
          platform: "linux",
          nodeVersion: "22.14.0",
          execFn: mockExec,
          fetchImpl: networkErrorFetch,
          checkPortListening: async () => true,
          exitImpl: (code) => {
            exitCode = code;
          }
        });
      } finally {
        console.log = origLog;
      }

      // WARN on network error does not trigger exit(1)
      expect(exitCode).toBeUndefined();
      expect(lines.some((l) => l.includes('WARN Account "personal" refresh network error'))).toBe(true);
    });

    it("fails when no extensions are paired", async () => {
      const { unitDir, mockExec, mockFetch } = await setupPassingEnv(tempDir);
      saveConfig({ allowedOrigins: [] }, tempDir);

      let exitCode: number | undefined;
      const lines: string[] = [];
      const origLog = console.log;
      console.log = (msg: string) => lines.push(msg);

      try {
        await doctorAction({
          homeDir: tempDir,
          unitDir,
          platform: "linux",
          nodeVersion: "22.14.0",
          execFn: mockExec,
          fetchImpl: mockFetch,
          checkPortListening: async () => true,
          exitImpl: (code) => {
            exitCode = code;
          }
        });
      } finally {
        console.log = origLog;
      }

      expect(exitCode).toBe(1);
      expect(lines.some((l) => l.includes("No extension paired. Run: autootp pair <extensionId>"))).toBe(true);
    });

    it("fails when service unit is missing or not active", async () => {
      const { unitDir, mockFetch } = await setupPassingEnv(tempDir);

      // Mock execFn where service is stopped
      const inactiveExec: ExecFunction = async (file, args) => {
        if (file === "systemctl" && args.includes("is-active")) {
          const err = new Error("inactive");
          (err as any).stdout = "inactive\n";
          throw err;
        }
        if (file === "which" && args.includes("notify-send")) {
          return { stdout: "/usr/bin/notify-send\n", stderr: "" };
        }
        return { stdout: "", stderr: "" };
      };

      let exitCode: number | undefined;
      const lines: string[] = [];
      const origLog = console.log;
      console.log = (msg: string) => lines.push(msg);

      try {
        await doctorAction({
          homeDir: tempDir,
          unitDir,
          platform: "linux",
          nodeVersion: "22.14.0",
          execFn: inactiveExec,
          fetchImpl: mockFetch,
          checkPortListening: async () => true,
          exitImpl: (code) => {
            exitCode = code;
          }
        });
      } finally {
        console.log = origLog;
      }

      expect(exitCode).toBe(1);
      expect(lines.some((l) => l.includes("Service installed but not running"))).toBe(true);
    });

    it("fails when port is not listening", async () => {
      const { unitDir, mockExec, mockFetch } = await setupPassingEnv(tempDir);

      let exitCode: number | undefined;
      const lines: string[] = [];
      const origLog = console.log;
      console.log = (msg: string) => lines.push(msg);

      try {
        await doctorAction({
          homeDir: tempDir,
          unitDir,
          platform: "linux",
          nodeVersion: "22.14.0",
          execFn: mockExec,
          fetchImpl: mockFetch,
          checkPortListening: async () => false,
          exitImpl: (code) => {
            exitCode = code;
          }
        });
      } finally {
        console.log = origLog;
      }

      expect(exitCode).toBe(1);
      expect(lines.some((l) => l.includes("Port 47821 is not listening"))).toBe(true);
    });

    it("fails when status file is missing or stale", async () => {
      const { unitDir, mockExec, mockFetch } = await setupPassingEnv(tempDir);
      // Remove status.json
      fs.unlinkSync(path.join(tempDir, "status.json"));

      let exitCode: number | undefined;
      const lines: string[] = [];
      const origLog = console.log;
      console.log = (msg: string) => lines.push(msg);

      try {
        await doctorAction({
          homeDir: tempDir,
          unitDir,
          platform: "linux",
          nodeVersion: "22.14.0",
          execFn: mockExec,
          fetchImpl: mockFetch,
          checkPortListening: async () => true,
          exitImpl: (code) => {
            exitCode = code;
          }
        });
      } finally {
        console.log = origLog;
      }

      expect(exitCode).toBe(1);
      expect(lines.some((l) => l.includes("Status file missing (service not running?)"))).toBe(true);
    });

    it("warns (not fails) when browser extension is not connected", async () => {
      const { unitDir, mockExec, mockFetch } = await setupPassingEnv(tempDir);
      // Update status to authedClients = 0
      writeStatus(
        {
          v: 1,
          pid: 1234,
          version: VERSION,
          startedAt: Date.now() - 30000,
          updatedAt: Date.now() - 1000,
          port: 47821,
          authedClients: 0,
          accounts: { personal: "ok" },
          lastOtp: null
        },
        tempDir
      );

      let exitCode: number | undefined;
      const lines: string[] = [];
      const origLog = console.log;
      console.log = (msg: string) => lines.push(msg);

      try {
        await doctorAction({
          homeDir: tempDir,
          unitDir,
          platform: "linux",
          nodeVersion: "22.14.0",
          execFn: mockExec,
          fetchImpl: mockFetch,
          checkPortListening: async () => true,
          exitImpl: (code) => {
            exitCode = code;
          }
        });
      } finally {
        console.log = origLog;
      }

      expect(exitCode).toBeUndefined();
      expect(lines.some((l) => l.includes("WARN Browser extension is not connected"))).toBe(true);
    });

    it("warns (not fails) when notification tool is missing", async () => {
      const { unitDir, mockFetch } = await setupPassingEnv(tempDir);

      const noNotifyExec: ExecFunction = async (file, args) => {
        if (file === "systemctl" && args.includes("is-active")) {
          return { stdout: "active\n", stderr: "" };
        }
        if (file === "which" && args.includes("notify-send")) {
          throw new Error("not found");
        }
        return { stdout: "", stderr: "" };
      };

      let exitCode: number | undefined;
      const lines: string[] = [];
      const origLog = console.log;
      console.log = (msg: string) => lines.push(msg);

      try {
        await doctorAction({
          homeDir: tempDir,
          unitDir,
          platform: "linux",
          nodeVersion: "22.14.0",
          execFn: noNotifyExec,
          fetchImpl: mockFetch,
          checkPortListening: async () => true,
          exitImpl: (code) => {
            exitCode = code;
          }
        });
      } finally {
        console.log = origLog;
      }

      expect(exitCode).toBeUndefined();
      expect(lines.some((l) => l.includes("WARN Notification tool missing (notify-send not found)"))).toBe(true);
    });

    it("never writes tokens, pair tokens, or OTP codes in doctor output", async () => {
      const { unitDir, mockExec, mockFetch } = await setupPassingEnv(tempDir);
      const secretToken = "super-secret-doctor-token-12345";
      const store = new TokenStore(tempDir);
      await store.set("personal", {
        refreshToken: secretToken,
        email: "user@example.com",
        addedAt: Date.now()
      });
      const pairToken = await pairAction("abcdefghijklmnopabcdefghijklmnop", { homeDir: tempDir });

      const lines: string[] = [];
      const origLog = console.log;
      console.log = (msg: string) => lines.push(msg);

      try {
        await doctorAction({
          homeDir: tempDir,
          unitDir,
          platform: "linux",
          nodeVersion: "22.14.0",
          execFn: mockExec,
          fetchImpl: mockFetch,
          checkPortListening: async () => true
        });
      } finally {
        console.log = origLog;
      }

      const allOutput = lines.join("\n");
      expect(allOutput).not.toContain(secretToken);
      expect(allOutput).not.toContain(pairToken);
      expect(allOutput).not.toMatch(/\b\d{6,8}\b/);
    });
  });

  describe("Audit Command", () => {
    beforeEach(() => {
      fs.writeFileSync(
        path.join(tempDir, "credentials.json"),
        JSON.stringify({
          installed: { client_id: "mock-id", client_secret: "mock-sec" }
        }),
        { mode: 0o600 }
      );
    });

    function makeMockMessage(options: {
      id: string;
      from: string;
      subject: string;
      body: string;
      authResults?: string;
    }) {
      const headers = [
        { name: "From", value: options.from },
        { name: "Subject", value: options.subject }
      ];
      if (options.authResults) {
        headers.push({ name: "Authentication-Results", value: options.authResults });
      }

      const encodedBody = Buffer.from(options.body).toString("base64url");
      return {
        id: options.id,
        payload: {
          headers,
          mimeType: "text/plain",
          body: { data: encodedBody }
        }
      };
    }

    it("validates --days and exits 1 for invalid values", async () => {
      const invalidValues = ["0", "61", "abc", "1.5", "-5"];
      for (const val of invalidValues) {
        let exitCode: number | undefined;
        const errLines: string[] = [];
        const origErr = console.error;
        console.error = (msg: string) => errLines.push(msg);

        try {
          await auditAction(
            { days: val },
            {
              homeDir: tempDir,
              exitImpl: (code) => {
                exitCode = code;
              }
            }
          );
        } finally {
          console.error = origErr;
        }

        expect(exitCode).toBe(1);
        expect(errLines.some((l) => l.includes(`Invalid value for --days: ${val}`))).toBe(true);
      }
    });

    it("correctly classifies each bucket: detected & verified, detected & unverified, possible miss, possible false positive", async () => {
      const store = new TokenStore(tempDir);
      await store.set("personal", {
        refreshToken: "mock-refresh-token",
        email: "test@example.com",
        addedAt: Date.now()
      });

      const mockMessages: Record<string, any> = {
        msg1: makeMockMessage({
          id: "msg1",
          from: "GitHub <noreply@github.com>",
          subject: "Your GitHub verification code",
          body: "Your verification code is 849201.",
          authResults: "mx.google.com; dmarc=pass header.from=github.com"
        }),
        msg2: makeMockMessage({
          id: "msg2",
          from: "Security <noreply@unverified.org>",
          subject: "Your security code",
          body: "Your verification code is 739102."
        }),
        msg3: makeMockMessage({
          id: "msg3",
          from: "Support <support@service.com>",
          subject: "Account Confirmation",
          body: "Your verification code was sent by SMS. Please click here to login."
        }),
        msg4: makeMockMessage({
          id: "msg4",
          from: "Alerts <alerts@mediumconf.com>",
          subject: "Your verification code",
          body: "Hello,\n\n483921\n\nThanks"
        }),
        msg5: makeMockMessage({
          id: "msg5",
          from: "System <system@strange.com>",
          subject: "Account Status",
          body: "12345678 is your Google verification code"
        })
      };

      const mockFetch: typeof fetch = async (input) => {
        const urlStr = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;

        if (urlStr.includes("oauth2.googleapis.com/token")) {
          return new Response(JSON.stringify({ access_token: "mock-access-token", expires_in: 3600 }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }

        if (urlStr.includes("gmail/v1/users/me/messages?")) {
          return new Response(
            JSON.stringify({
              messages: Object.keys(mockMessages).map((id) => ({ id }))
            }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          );
        }

        for (const [id, msgData] of Object.entries(mockMessages)) {
          if (urlStr.includes(`gmail/v1/users/me/messages/${id}`)) {
            return new Response(JSON.stringify(msgData), {
              status: 200,
              headers: { "Content-Type": "application/json" }
            });
          }
        }

        return new Response("Not Found", { status: 404 });
      };

      const lines: string[] = [];
      const origLog = console.log;
      console.log = (msg: string) => lines.push(msg);

      try {
        await auditAction(
          { days: 14, subjects: true },
          {
            homeDir: tempDir,
            fetchImpl: mockFetch,
            initialBackoffMs: 1,
            sleepFn: async () => {}
          }
        );
      } finally {
        console.log = origLog;
      }

      const out = lines.join("\n");
      expect(out).toContain("Scanned: 5");
      expect(out).toContain("Detected: 4");
      expect(out).toContain("Detected and verified: 1");
      expect(out).toContain("Detected and unverified: 3");
      expect(out).toContain("Possible misses: 1");
      expect(out).toContain("Possible false positives: 2");

      expect(out).toContain("github.com: 1");
      expect(out).toContain("unverified.org: 1");
      expect(out).toContain("service.com: 1");
      expect(out).toContain("mediumconf.com: 1");
      expect(out).toContain("strange.com: 1");
    });

    it("respects the 200 message cap when paginating", async () => {
      const store = new TokenStore(tempDir);
      await store.set("personal", {
        refreshToken: "mock-refresh-token",
        email: "test@example.com",
        addedAt: Date.now()
      });

      let page3Fetched = false;
      const fetchedIds: string[] = [];

      const mockFetch: typeof fetch = async (input) => {
        const urlStr = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;

        if (urlStr.includes("oauth2.googleapis.com/token")) {
          return new Response(JSON.stringify({ access_token: "mock-access-token", expires_in: 3600 }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }

        if (urlStr.includes("gmail/v1/users/me/messages?")) {
          if (urlStr.includes("pageToken=page2")) {
            const messages = Array.from({ length: 100 }, (_, i) => ({ id: `msg-${i + 101}` }));
            return new Response(JSON.stringify({ messages, nextPageToken: "page3" }), {
              status: 200,
              headers: { "Content-Type": "application/json" }
            });
          }
          if (urlStr.includes("pageToken=page3")) {
            page3Fetched = true;
            const messages = Array.from({ length: 50 }, (_, i) => ({ id: `msg-${i + 201}` }));
            return new Response(JSON.stringify({ messages }), {
              status: 200,
              headers: { "Content-Type": "application/json" }
            });
          }
          const messages = Array.from({ length: 100 }, (_, i) => ({ id: `msg-${i + 1}` }));
          return new Response(JSON.stringify({ messages, nextPageToken: "page2" }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }

        const match = urlStr.match(/gmail\/v1\/users\/me\/messages\/(msg-\d+)/);
        if (match) {
          fetchedIds.push(match[1]);
          const msgData = makeMockMessage({
            id: match[1],
            from: "Acme <noreply@acme.com>",
            subject: "Update",
            body: "No code here."
          });
          return new Response(JSON.stringify(msgData), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }

        return new Response("Not Found", { status: 404 });
      };

      const lines: string[] = [];
      const origLog = console.log;
      console.log = (msg: string) => lines.push(msg);

      try {
        await auditAction(
          { days: 14 },
          {
            homeDir: tempDir,
            fetchImpl: mockFetch,
            initialBackoffMs: 1,
            sleepFn: async () => {}
          }
        );
      } finally {
        console.log = origLog;
      }

      expect(page3Fetched).toBe(false);
      expect(fetchedIds.length).toBe(200);
      expect(lines.join("\n")).toContain("Scanned: 200");
    });

    it("backs off and retries on 429 response", async () => {
      const store = new TokenStore(tempDir);
      await store.set("personal", {
        refreshToken: "mock-refresh-token",
        email: "test@example.com",
        addedAt: Date.now()
      });

      let attempts429 = 0;
      const sleepCalls: number[] = [];
      const mockSleep = async (ms: number) => {
        sleepCalls.push(ms);
      };

      const mockFetch: typeof fetch = async (input) => {
        const urlStr = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;

        if (urlStr.includes("oauth2.googleapis.com/token")) {
          return new Response(JSON.stringify({ access_token: "mock-access-token", expires_in: 3600 }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }

        if (urlStr.includes("gmail/v1/users/me/messages?")) {
          return new Response(JSON.stringify({ messages: [{ id: "msg-retry" }] }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }

        if (urlStr.includes("gmail/v1/users/me/messages/msg-retry")) {
          attempts429++;
          if (attempts429 === 1) {
            return new Response("Too Many Requests", { status: 429 });
          }
          const msgData = makeMockMessage({
            id: "msg-retry",
            from: "Service <service@acme.com>",
            subject: "Your code",
            body: "Your verification code is 123456."
          });
          return new Response(JSON.stringify(msgData), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }

        return new Response("Not Found", { status: 404 });
      };

      const lines: string[] = [];
      const origLog = console.log;
      console.log = (msg: string) => lines.push(msg);

      try {
        await auditAction(
          { days: 14 },
          {
            homeDir: tempDir,
            fetchImpl: mockFetch,
            initialBackoffMs: 50,
            sleepFn: mockSleep
          }
        );
      } finally {
        console.log = origLog;
      }

      expect(attempts429).toBe(2);
      expect(sleepCalls.length).toBeGreaterThanOrEqual(1);
      expect(sleepCalls[0]).toBe(50);
      expect(lines.join("\n")).toContain("Scanned: 1");
      expect(lines.join("\n")).toContain("Detected: 1");
    });

    it("handles expired account with message and continues to audit other accounts", async () => {
      const store = new TokenStore(tempDir);
      await store.set("expired-acct", {
        refreshToken: "expired-refresh-token",
        email: "expired@example.com",
        addedAt: Date.now() - 1000
      });
      await store.set("active-acct", {
        refreshToken: "active-refresh-token",
        email: "active@example.com",
        addedAt: Date.now()
      });

      const mockFetch: typeof fetch = async (input, init) => {
        const urlStr = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;

        if (urlStr.includes("oauth2.googleapis.com/token")) {
          const bodyStr = String(init?.body ?? "");
          if (bodyStr.includes("expired-refresh-token")) {
            return new Response(JSON.stringify({ error: "invalid_grant" }), {
              status: 400,
              headers: { "Content-Type": "application/json" }
            });
          }
          return new Response(JSON.stringify({ access_token: "active-token", expires_in: 3600 }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }

        if (urlStr.includes("gmail/v1/users/me/messages?")) {
          return new Response(JSON.stringify({ messages: [{ id: "active-msg" }] }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }

        if (urlStr.includes("gmail/v1/users/me/messages/active-msg")) {
          const msgData = makeMockMessage({
            id: "active-msg",
            from: "Service <service@active.com>",
            subject: "Security Alert",
            body: "Your verification code is 654321."
          });
          return new Response(JSON.stringify(msgData), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }

        return new Response("Not Found", { status: 404 });
      };

      const lines: string[] = [];
      const origLog = console.log;
      console.log = (msg: string) => lines.push(msg);

      try {
        await auditAction(
          { days: 14 },
          {
            homeDir: tempDir,
            fetchImpl: mockFetch,
            initialBackoffMs: 1,
            sleepFn: async () => {}
          }
        );
      } finally {
        console.log = origLog;
      }

      const out = lines.join("\n");
      expect(out).toContain("expired-acct: Google access expired. Run: autootp login expired-acct");
      expect(out).toContain("Scanned: 1");
      expect(out).toContain("active.com: 1");
    });

    it("never leaks sentinel code, body text, message ID, or token in output, and only shows subjects when --subjects is enabled", async () => {
      const store = new TokenStore(tempDir);
      const sentinelToken = "SENTINEL_TOKEN_SECRET_987654";
      await store.set("personal", {
        refreshToken: sentinelToken,
        email: "personal@example.com",
        addedAt: Date.now()
      });

      const sentinelCode = "998877";
      const sentinelBody = "SENTINEL_EMAIL_BODY_TEXT_XYZ";
      const sentinelMsgId = "SENTINEL_MSG_ID_ABCDEF";
      const testSubject = "Unique Subject For Audit Calibration";

      const mockFetch: typeof fetch = async (input) => {
        const urlStr = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;

        if (urlStr.includes("oauth2.googleapis.com/token")) {
          return new Response(JSON.stringify({ access_token: "mock-access-token", expires_in: 3600 }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }

        if (urlStr.includes("gmail/v1/users/me/messages?")) {
          return new Response(JSON.stringify({ messages: [{ id: sentinelMsgId }] }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }

        if (urlStr.includes(sentinelMsgId)) {
          const msgData = makeMockMessage({
            id: sentinelMsgId,
            from: "Auth <auth@example.com>",
            subject: testSubject,
            body: `${sentinelBody}\nYour verification code is ${sentinelCode}.`
          });
          return new Response(JSON.stringify(msgData), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }

        return new Response("Not Found", { status: 404 });
      };

      // 1. Without --subjects
      const linesWithoutSubjects: string[] = [];
      const origLog = console.log;
      console.log = (msg: string) => linesWithoutSubjects.push(msg);

      try {
        await auditAction(
          { days: 14, subjects: false },
          {
            homeDir: tempDir,
            fetchImpl: mockFetch,
            initialBackoffMs: 1,
            sleepFn: async () => {}
          }
        );
      } finally {
        console.log = origLog;
      }

      const outWithout = linesWithoutSubjects.join("\n");
      expect(outWithout).not.toContain(sentinelCode);
      expect(outWithout).not.toContain(sentinelBody);
      expect(outWithout).not.toContain(sentinelToken);
      expect(outWithout).not.toContain(sentinelMsgId);
      expect(outWithout).not.toContain(testSubject);

      // 2. With --subjects
      const linesWithSubjects: string[] = [];
      console.log = (msg: string) => linesWithSubjects.push(msg);

      try {
        await auditAction(
          { days: 14, subjects: true },
          {
            homeDir: tempDir,
            fetchImpl: mockFetch,
            initialBackoffMs: 1,
            sleepFn: async () => {}
          }
        );
      } finally {
        console.log = origLog;
      }

      const outWith = linesWithSubjects.join("\n");
      expect(outWith).toContain(testSubject);
      expect(outWith).not.toContain(sentinelCode);
      expect(outWith).not.toContain(sentinelBody);
      expect(outWith).not.toContain(sentinelToken);
      expect(outWith).not.toContain(sentinelMsgId);
    });

    it("--explain output never contains the sentinel code or any email local part", async () => {
      const store = new TokenStore(tempDir);
      const sentinelToken = "SENTINEL_TOKEN_SECRET_987654";
      await store.set("personal", {
        refreshToken: sentinelToken,
        email: "personal@example.com",
        addedAt: Date.now()
      });

      const sentinelCode = "987654";
      const sentinelLocalPart = "secret_user_local_part";
      const sentinelDomain = "unverified-sender.com";

      const mockFetch: typeof fetch = async (input) => {
        const urlStr = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;

        if (urlStr.includes("oauth2.googleapis.com/token")) {
          return new Response(JSON.stringify({ access_token: "mock-access-token", expires_in: 3600 }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }

        if (urlStr.includes("gmail/v1/users/me/messages?")) {
          return new Response(JSON.stringify({ messages: [{ id: "msg-unverified" }] }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }

        if (urlStr.includes("msg-unverified")) {
          const msgData = makeMockMessage({
            id: "msg-unverified",
            from: `Secret Admin <${sentinelLocalPart}@${sentinelDomain}>`,
            subject: "Your verification code",
            body: `Hello ${sentinelLocalPart}, your code is ${sentinelCode}. Please keep it secret.`,
            authResults: `mx.google.com; dkim=pass header.i=${sentinelLocalPart}@${sentinelDomain}; spf=pass smtp.mailfrom="${sentinelLocalPart}@${sentinelDomain}"; dmarc=fail header.from=${sentinelDomain}`
          });
          return new Response(JSON.stringify(msgData), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }

        return new Response("Not Found", { status: 404 });
      };

      const lines: string[] = [];
      const origLog = console.log;
      console.log = (msg: string) => lines.push(msg);

      try {
        await auditAction(
          { days: 14, explain: true },
          {
            homeDir: tempDir,
            fetchImpl: mockFetch,
            initialBackoffMs: 1,
            sleepFn: async () => {}
          }
        );
      } finally {
        console.log = origLog;
      }

      const out = lines.join("\n");
      expect(out).toContain("Explain:");
      expect(out).toContain("Unverified senders:");
      expect(out).toContain(`domain: ${sentinelDomain}`);
      expect(out).toContain("<CODE:6 digits>");
      expect(out).toContain("authserv-id=mx.google.com");
      expect(out).toContain(`smtp.mailfrom=${sentinelDomain}`);
      expect(out).toContain("dmarc=fail");

      // Verify NEVER leaks sentinel code or email local part:
      expect(out).not.toContain(sentinelCode);
      expect(out).not.toContain(sentinelLocalPart);
      expect(out).not.toContain(sentinelToken);
    });

    it("--explain respects the context length cap (never more than 100 characters)", async () => {
      const store = new TokenStore(tempDir);
      await store.set("personal", {
        refreshToken: "mock-token",
        email: "personal@example.com",
        addedAt: Date.now()
      });

      const longBefore = "A".repeat(150);
      const longAfter = "B".repeat(150);

      const mockFetch: typeof fetch = async (input) => {
        const urlStr = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;

        if (urlStr.includes("oauth2.googleapis.com/token")) {
          return new Response(JSON.stringify({ access_token: "mock-token", expires_in: 3600 }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }

        if (urlStr.includes("gmail/v1/users/me/messages?")) {
          return new Response(JSON.stringify({ messages: [{ id: "msg-long" }] }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }

        if (urlStr.includes("msg-long")) {
          const msgData = makeMockMessage({
            id: "msg-long",
            from: "Service <service@test.com>",
            subject: "Your code",
            body: `${longBefore} 849201 ${longAfter}`
          });
          return new Response(JSON.stringify(msgData), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }

        return new Response("Not Found", { status: 404 });
      };

      const lines: string[] = [];
      const origLog = console.log;
      console.log = (msg: string) => lines.push(msg);

      try {
        await auditAction(
          { days: 14, explain: true },
          {
            homeDir: tempDir,
            fetchImpl: mockFetch,
            initialBackoffMs: 1,
            sleepFn: async () => {}
          }
        );
      } finally {
        console.log = origLog;
      }

      const contextLine = lines.find((l) => l.trim().startsWith("context:"));
      expect(contextLine).toBeDefined();
      const contextText = contextLine!.replace(/^.*context:\s*/, "");
      expect(contextText.length).toBeLessThanOrEqual(100);
      expect(contextText).toContain("<CODE:6 digits>");
    });

    it("--explain masks other digit runs of 4 or more digits with <N>", async () => {
      const store = new TokenStore(tempDir);
      await store.set("personal", {
        refreshToken: "mock-token",
        email: "personal@example.com",
        addedAt: Date.now()
      });

      const mockFetch: typeof fetch = async (input) => {
        const urlStr = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;

        if (urlStr.includes("oauth2.googleapis.com/token")) {
          return new Response(JSON.stringify({ access_token: "mock-token", expires_in: 3600 }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }

        if (urlStr.includes("gmail/v1/users/me/messages?")) {
          return new Response(JSON.stringify({ messages: [{ id: "msg-digits" }] }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }

        if (urlStr.includes("msg-digits")) {
          const msgData = makeMockMessage({
            id: "msg-digits",
            from: "Service <service@digits.com>",
            subject: "Your code",
            body: "Your verification code is 123456. Order #998877 and pin 5432, ref 123."
          });
          return new Response(JSON.stringify(msgData), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }

        return new Response("Not Found", { status: 404 });
      };

      const lines: string[] = [];
      const origLog = console.log;
      console.log = (msg: string) => lines.push(msg);

      try {
        await auditAction(
          { days: 14, explain: true },
          {
            homeDir: tempDir,
            fetchImpl: mockFetch,
            initialBackoffMs: 1,
            sleepFn: async () => {}
          }
        );
      } finally {
        console.log = origLog;
      }

      const out = lines.join("\n");
      const contextLine = lines.find((l) => l.trim().startsWith("context:"));
      expect(contextLine).toBeDefined();
      expect(contextLine).toContain("<CODE:6 digits>");
      expect(contextLine).toContain("<N>");
      expect(contextLine).toContain("123"); // 3 digits not replaced
      expect(contextLine).not.toContain("998877");
      expect(contextLine).not.toContain("5432");
      expect(out).not.toMatch(/\b\d{6,}\b/);
    });

    it("leaves default output unchanged without --explain", async () => {
      const store = new TokenStore(tempDir);
      await store.set("personal", {
        refreshToken: "mock-token",
        email: "personal@example.com",
        addedAt: Date.now()
      });

      const mockFetch: typeof fetch = async (input) => {
        const urlStr = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;

        if (urlStr.includes("oauth2.googleapis.com/token")) {
          return new Response(JSON.stringify({ access_token: "mock-token", expires_in: 3600 }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }

        if (urlStr.includes("gmail/v1/users/me/messages?")) {
          return new Response(JSON.stringify({ messages: [{ id: "msg-default" }] }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }

        if (urlStr.includes("msg-default")) {
          const msgData = makeMockMessage({
            id: "msg-default",
            from: "Service <service@test.com>",
            subject: "Your verification code",
            body: "Your code is 654321."
          });
          return new Response(JSON.stringify(msgData), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }

        return new Response("Not Found", { status: 404 });
      };

      const lines: string[] = [];
      const origLog = console.log;
      console.log = (msg: string) => lines.push(msg);

      try {
        await auditAction(
          { days: 14, explain: false },
          {
            homeDir: tempDir,
            fetchImpl: mockFetch,
            initialBackoffMs: 1,
            sleepFn: async () => {}
          }
        );
      } finally {
        console.log = origLog;
      }

      const out = lines.join("\n");
      expect(out).toContain("Summary:");
      expect(out).toContain("Detected senders:");
      expect(out).not.toContain("Explain:");
      expect(out).not.toContain("context:");
      expect(out).not.toContain("auth:");
    });
  });
});



