import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { WebSocket } from "ws";
import {
  TokenStore,
  saveConfig,
  getOrCreatePairToken,
  HistoryStore,
  readStatus
} from "@autootp/shared";
import {
  startService,
  sanitizeNotificationText,
  DesktopNotifier,
  MACOS_NOTIFICATION_SCRIPT
} from "./index.js";
import { ReauthRequiredError } from "@autootp/gmail";

function waitForOpen(ws: WebSocket): Promise<void> {
  return new Promise((resolve, reject) => {
    ws.on("open", resolve);
    ws.on("error", reject);
  });
}

function waitForMessage(ws: WebSocket): Promise<any> {
  return new Promise((resolve, reject) => {
    ws.once("message", (data) => {
      try {
        resolve(JSON.parse(data.toString()));
      } catch (err) {
        reject(err);
      }
    });
    ws.once("error", reject);
  });
}

describe("AutoOTP Service (packages/service)", () => {
  let tempDir: string;
  const originalHome = process.env.AUTOOTP_HOME;
  const validExtensionOrigin = `chrome-extension://${"a".repeat(32)}`;

  beforeEach(() => {
    const tmpBase = process.env.TMPDIR || process.env.TEMP || "/tmp";
    tempDir = fs.mkdtempSync(path.join(tmpBase, "autootp-service-test-"));
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

  it("service refuses without paired origins", async () => {
    // Default config has empty allowedOrigins
    await expect(startService({ homeDir: tempDir })).rejects.toThrow(
      "No extension paired. Run: autootp pair <extensionId>"
    );
  });

  it("service refuses with no accounts connected when noWatch is false", async () => {
    saveConfig(
      {
        allowedOrigins: [validExtensionOrigin],
        port: 47821,
        pollMs: 3000
      },
      tempDir
    );

    // No accounts in TokenStore
    await expect(startService({ homeDir: tempDir, noWatch: false })).rejects.toThrow(
      "No accounts connected. Run: autootp login"
    );
  });

  it("EADDRINUSE gives the friendly message", async () => {
    // Start an existing HTTP server to occupy a port
    const dummyServer = http.createServer();
    const occupiedPort = await new Promise<number>((resolve) => {
      dummyServer.listen(0, "127.0.0.1", () => {
        resolve((dummyServer.address() as any).port);
      });
    });

    try {
      saveConfig(
        {
          allowedOrigins: [validExtensionOrigin],
          port: occupiedPort,
          pollMs: 3000
        },
        tempDir
      );

      await expect(
        startService({ homeDir: tempDir, noWatch: true })
      ).rejects.toThrow(
        `Port ${occupiedPort} in use. Is AutoOTP already running?`
      );
    } finally {
      await new Promise<void>((resolve) => {
        dummyServer.close(() => resolve());
      });
    }
  });

  it("the service broadcasts an OTP from a mocked watcher to a real authenticated ws client", async () => {
    const store = new TokenStore(tempDir);
    await store.set("personal", {
      refreshToken: "refresh-token-test",
      email: "personal@example.com",
      addedAt: Date.now()
    });

    fs.writeFileSync(
      path.join(tempDir, "credentials.json"),
      JSON.stringify({
        installed: {
          client_id: "test-client-id",
          client_secret: "test-client-secret"
        }
      })
    );

    const dummyServer = http.createServer();
    const testPort = await new Promise<number>((resolve) => {
      dummyServer.listen(0, "127.0.0.1", () => {
        const addr = dummyServer.address() as any;
        dummyServer.close(() => resolve(addr.port));
      });
    });

    saveConfig(
      {
        allowedOrigins: [validExtensionOrigin],
        port: testPort,
        pollMs: 10
      },
      tempDir
    );

    const token = getOrCreatePairToken(tempDir);
    const controller = new AbortController();

    let wsReady = false;
    const mockFetch = async (input: RequestInfo | URL): Promise<Response> => {
      const urlStr = input.toString();
      if (urlStr.includes("oauth2.googleapis.com/token")) {
        return new Response(
          JSON.stringify({ access_token: "mock-access-token", expires_in: 3600 }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
      if (urlStr.includes("/profile")) {
        return new Response(JSON.stringify({ historyId: "100" }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (urlStr.includes("/messages?labelIds=")) {
        return new Response(JSON.stringify({ messages: [] }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (urlStr.includes("/history")) {
        if (!wsReady) {
          return new Response(JSON.stringify({ history: [], historyId: "100" }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
        return new Response(
          JSON.stringify({
            history: [
              {
                messagesAdded: [{ message: { id: "msg-service-42" } }]
              }
            ],
            historyId: "101"
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
      if (urlStr.includes("/messages/msg-service-42?format=full")) {
        return new Response(
          JSON.stringify({
            id: "msg-service-42",
            internalDate: String(Date.now()),
            payload: {
              headers: [
                { name: "Subject", value: "Your verification code" },
                { name: "From", value: "Service <service@example.com>" }
              ],
              mimeType: "text/plain",
              body: {
                data: Buffer.from("Your security code is 782103.").toString("base64url")
              }
            }
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
      return new Response("Not found", { status: 404 });
    };

    let receivedOtp: any = null;

    await startService({
      homeDir: tempDir,
      fetchImpl: mockFetch as typeof fetch,
      signal: controller.signal,
      onStarted: async ({ port }) => {
        const ws = new WebSocket(`ws://127.0.0.1:${port}`, {
          headers: { Origin: validExtensionOrigin }
        });

        await waitForOpen(ws);

        // Authenticate
        const helloPromise = waitForMessage(ws);
        ws.send(JSON.stringify({ type: "auth", token }));
        const hello = await helloPromise;
        expect(hello).toEqual({ type: "hello", version: 1 });

        // Ready to receive OTP
        const otpMsgPromise = waitForMessage(ws);
        wsReady = true;
        receivedOtp = await otpMsgPromise;

        ws.close();
        controller.abort();
      }
    });

    expect(receivedOtp).toBeTruthy();
    expect(receivedOtp.type).toBe("otp");
    expect(receivedOtp.id).toBe("msg-service-42");
    expect(receivedOtp.account).toBe("personal");
    expect(receivedOtp.code).toBe("782103");
    expect(receivedOtp.sender).toBe("Service");
    expect(receivedOtp.senderVerified).toBe(false);

    // Verify OTP was saved to history
    const historyStore = new HistoryStore(tempDir);
    const historyEntries = historyStore.list();
    expect(historyEntries).toHaveLength(1);
    expect(historyEntries[0].code).toBe("782103");
    expect(historyEntries[0].sender).toBe("Service");
    expect(historyEntries[0].alias).toBe("personal");
    historyStore.close();

    // Verify status file is removed on graceful shutdown
    expect(readStatus(tempDir)).toBeNull();
  });

  it("updates status file on start, client auth, otp, and removes on shutdown without codes", async () => {
    const store = new TokenStore(tempDir);
    await store.set("personal", {
      refreshToken: "refresh-token-test",
      email: "personal@example.com",
      addedAt: Date.now()
    });

    fs.writeFileSync(
      path.join(tempDir, "credentials.json"),
      JSON.stringify({
        installed: {
          client_id: "test-client-id",
          client_secret: "test-client-secret"
        }
      })
    );

    const dummyServer = http.createServer();
    const testPort = await new Promise<number>((resolve) => {
      dummyServer.listen(0, "127.0.0.1", () => {
        const addr = dummyServer.address() as any;
        dummyServer.close(() => resolve(addr.port));
      });
    });

    saveConfig(
      {
        allowedOrigins: [validExtensionOrigin],
        port: testPort,
        pollMs: 10
      },
      tempDir
    );

    const token = getOrCreatePairToken(tempDir);
    const controller = new AbortController();

    const sentinelCode = "829104";
    let wsReady = false;
    const mockFetch = async (input: RequestInfo | URL): Promise<Response> => {
      const urlStr = input.toString();
      if (urlStr.includes("oauth2.googleapis.com/token")) {
        return new Response(
          JSON.stringify({ access_token: "mock-access-token", expires_in: 3600 }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
      if (urlStr.includes("/profile")) {
        return new Response(JSON.stringify({ historyId: "100" }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (urlStr.includes("/messages?labelIds=")) {
        return new Response(JSON.stringify({ messages: [] }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (urlStr.includes("/history")) {
        if (!wsReady) {
          return new Response(JSON.stringify({ history: [], historyId: "100" }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
        return new Response(
          JSON.stringify({
            history: [{ messagesAdded: [{ message: { id: "msg-service-status" } }] }],
            historyId: "101"
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
      if (urlStr.includes("/messages/msg-service-status?format=full")) {
        return new Response(
          JSON.stringify({
            id: "msg-service-status",
            internalDate: String(Date.now()),
            payload: {
              headers: [
                { name: "Subject", value: "Your verification code" },
                { name: "From", value: "GitHub <security@github.com>" }
              ],
              mimeType: "text/plain",
              body: {
                data: Buffer.from(`Your code is ${sentinelCode}.`).toString("base64url")
              }
            }
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
      return new Response("Not found", { status: 404 });
    };

    let statusOnStart: any = null;
    let statusOnAuth: any = null;
    let statusOnOtp: any = null;

    await startService({
      homeDir: tempDir,
      fetchImpl: mockFetch as typeof fetch,
      signal: controller.signal,
      onStarted: async ({ port }) => {
        // 1. Status on start
        statusOnStart = readStatus(tempDir);

        const ws = new WebSocket(`ws://127.0.0.1:${port}`, {
          headers: { Origin: validExtensionOrigin }
        });

        await waitForOpen(ws);
        const helloPromise = waitForMessage(ws);
        ws.send(JSON.stringify({ type: "auth", token }));
        await helloPromise;

        // 2. Status on client auth
        statusOnAuth = readStatus(tempDir);

        // 3. Receive OTP
        const otpMsgPromise = waitForMessage(ws);
        wsReady = true;
        await otpMsgPromise;

        statusOnOtp = readStatus(tempDir);

        // Verify status file on disk contains NO sentinel code or tokens
        const rawStatus = fs.readFileSync(path.join(tempDir, "status.json"), "utf8");
        expect(rawStatus).not.toContain(sentinelCode);
        expect(rawStatus).not.toContain(token);
        expect(rawStatus).not.toContain("code");

        ws.close();
        controller.abort();
      }
    });

    expect(statusOnStart).toBeTruthy();
    expect(statusOnStart.authedClients).toBe(0);
    expect(statusOnStart.accounts).toEqual({ personal: "ok" });
    expect(statusOnStart.lastOtp).toBeNull();

    expect(statusOnAuth).toBeTruthy();
    expect(statusOnAuth.authedClients).toBe(1);

    expect(statusOnOtp).toBeTruthy();
    expect(statusOnOtp.lastOtp).toEqual({
      sender: "GitHub",
      senderDomain: "github.com",
      at: expect.any(Number)
    });

    // 4. Status removed on shutdown
    expect(readStatus(tempDir)).toBeNull();
  });
});

describe("Desktop Notifications (packages/service)", () => {
  let tempDir: string;
  const originalHome = process.env.AUTOOTP_HOME;

  beforeEach(() => {
    const tmpBase = process.env.TMPDIR || process.env.TEMP || "/tmp";
    tempDir = fs.mkdtempSync(path.join(tmpBase, "autootp-notifier-test-"));
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

  describe("sanitizeNotificationText", () => {
    it("sanitizes markup and replaces < > & with spaces", () => {
      const input = "<b>Hello & World</b> <tag>";
      const result = sanitizeNotificationText(input);
      expect(result).toBe("b Hello World /b tag");
      expect(result).not.toContain("<");
      expect(result).not.toContain(">");
      expect(result).not.toContain("&");
    });

    it("removes newlines", () => {
      const input = "Line1\r\nLine2\nLine3";
      const result = sanitizeNotificationText(input);
      expect(result).toBe("Line1Line2Line3");
      expect(result).not.toContain("\n");
      expect(result).not.toContain("\r");
    });

    it("removes control characters", () => {
      const input = "Hello\u0007\x00\x1fWorld\x7f";
      const result = sanitizeNotificationText(input);
      expect(result).toBe("HelloWorld");
      expect(/[\x00-\x1f\x7f]/.test(result)).toBe(false);
    });

    it("strips leading dashes and spaces while preserving internal dashes", () => {
      expect(sanitizeNotificationText("--flag")).toBe("flag");
      expect(sanitizeNotificationText("-flag")).toBe("flag");
      expect(sanitizeNotificationText("- -flag")).toBe("flag");
      expect(sanitizeNotificationText("foo-bar")).toBe("foo-bar");
      expect(sanitizeNotificationText("service - backup")).toBe("service - backup");
      expect(sanitizeNotificationText("--")).toBe("Unknown sender");
      expect(sanitizeNotificationText("---")).toBe("Unknown sender");
      expect(sanitizeNotificationText("   ---   ")).toBe("Unknown sender");
    });

    it("cuts to max characters (default 40 and custom max)", () => {
      const longInput = "a".repeat(80);
      const defaultSanitized = sanitizeNotificationText(longInput);
      expect(defaultSanitized).toHaveLength(40);
      expect(defaultSanitized).toBe("a".repeat(40));

      const customSanitized = sanitizeNotificationText(longInput, 15);
      expect(customSanitized).toHaveLength(15);
      expect(customSanitized).toBe("a".repeat(15));
    });

    it("returns 'Unknown sender' for empty or whitespace or stripped-empty inputs", () => {
      expect(sanitizeNotificationText("")).toBe("Unknown sender");
      expect(sanitizeNotificationText("   ")).toBe("Unknown sender");
      expect(sanitizeNotificationText("\n\r\t \u0007")).toBe("Unknown sender");
      expect(sanitizeNotificationText("<>&")).toBe("Unknown sender");
      expect(sanitizeNotificationText(null as any)).toBe("Unknown sender");
      expect(sanitizeNotificationText(undefined as any)).toBe("Unknown sender");
    });
  });

  describe("Notifier execution and exact argument arrays", () => {
    it("passes exact argument array for Linux (notify-send)", async () => {
      const calls: Array<{ file: string; args: string[] }> = [];
      const mockExec = async (file: string, args: string[]) => {
        calls.push({ file, args });
      };

      const notifier = new DesktopNotifier({
        homeDir: tempDir,
        platform: "linux",
        execFn: mockExec
      });

      await notifier.send("AutoOTP: GitHub", "Code: 123456");

      expect(calls).toHaveLength(1);
      expect(calls[0]).toEqual({
        file: "notify-send",
        args: [
          "-a",
          "AutoOTP",
          "-t",
          "15000",
          "-h",
          "int:transient:1",
          "--",
          "AutoOTP: GitHub",
          "Code: 123456"
        ]
      });
    });

    it("passes exact argument array for macOS (osascript)", async () => {
      const calls: Array<{ file: string; args: string[] }> = [];
      const mockExec = async (file: string, args: string[]) => {
        calls.push({ file, args });
      };

      const notifier = new DesktopNotifier({
        homeDir: tempDir,
        platform: "darwin",
        execFn: mockExec
      });

      await notifier.send("AutoOTP: GitHub", "Code: 123456");

      expect(calls).toHaveLength(1);
      expect(calls[0]).toEqual({
        file: "osascript",
        args: ["-e", MACOS_NOTIFICATION_SCRIPT, "AutoOTP: GitHub", "Code: 123456"]
      });
    });

    it("does nothing and never throws on Windows", async () => {
      const calls: Array<{ file: string; args: string[] }> = [];
      const mockExec = async (file: string, args: string[]) => {
        calls.push({ file, args });
      };

      const notifier = new DesktopNotifier({
        homeDir: tempDir,
        platform: "win32",
        execFn: mockExec
      });

      await expect(notifier.send("AutoOTP: GitHub", "Code: 123456")).resolves.not.toThrow();
      expect(calls).toHaveLength(0);
    });

    it("catches and ignores notification command failures without throwing", async () => {
      const failingExec = async () => {
        throw new Error("Command failed: notify-send: command not found");
      };

      const notifier = new DesktopNotifier({
        homeDir: tempDir,
        platform: "linux",
        execFn: failingExec
      });

      await expect(notifier.send("Title", "Body")).resolves.not.toThrow();
      await expect(notifier.notifyOtp("GitHub", "123456")).resolves.not.toThrow();
      await expect(notifier.notifyExpiry("personal")).resolves.not.toThrow();
    });
  });

  describe("Three notification modes and dynamic config reloading", () => {
    it("mode 'code' shows sender in title and code in body", async () => {
      const calls: Array<{ file: string; args: string[] }> = [];
      const notifier = new DesktopNotifier({
        homeDir: tempDir,
        platform: "linux",
        execFn: async (file, args) => {
          calls.push({ file, args });
        }
      });

      saveConfig({ notifications: "code" }, tempDir);
      await notifier.notifyOtp("GitHub", "987654");

      expect(calls).toHaveLength(1);
      const [title, body] = calls[0].args.slice(7);
      expect(title).toBe("AutoOTP: GitHub");
      expect(body).toBe("Code: 987654");
    });

    it("mode 'hidden' shows title and 'New code received' with no digits anywhere", async () => {
      const calls: Array<{ file: string; args: string[] }> = [];
      const notifier = new DesktopNotifier({
        homeDir: tempDir,
        platform: "linux",
        execFn: async (file, args) => {
          calls.push({ file, args });
        }
      });

      saveConfig({ notifications: "hidden" }, tempDir);
      await notifier.notifyOtp("GitHub", "987654");

      expect(calls).toHaveLength(1);
      const [title, body] = calls[0].args.slice(7);
      expect(title).toBe("AutoOTP: GitHub");
      expect(body).toBe("New code received");
      // Must contain NO digits anywhere
      expect(/\d/.test(body)).toBe(false);
      expect(title).not.toContain("987654");
      expect(body).not.toContain("987654");
    });

    it("mode 'off' sends no notification for OTP codes", async () => {
      const calls: Array<{ file: string; args: string[] }> = [];
      const notifier = new DesktopNotifier({
        homeDir: tempDir,
        platform: "linux",
        execFn: async (file, args) => {
          calls.push({ file, args });
        }
      });

      saveConfig({ notifications: "off" }, tempDir);
      await notifier.notifyOtp("GitHub", "987654");

      expect(calls).toHaveLength(0);
    });

    it("reloads config on every notification without restart", async () => {
      const calls: Array<{ file: string; args: string[] }> = [];
      const notifier = new DesktopNotifier({
        homeDir: tempDir,
        platform: "linux",
        execFn: async (file, args) => {
          calls.push({ file, args });
        }
      });

      // Default / code
      saveConfig({ notifications: "code" }, tempDir);
      await notifier.notifyOtp("GitHub", "111111");
      expect(calls[0].args[8]).toBe("Code: 111111");

      // Switch to hidden
      saveConfig({ notifications: "hidden" }, tempDir);
      await notifier.notifyOtp("GitHub", "222222");
      expect(calls[1].args[8]).toBe("New code received");
      expect(/\d/.test(calls[1].args[8])).toBe(false);

      // Switch to off
      saveConfig({ notifications: "off" }, tempDir);
      await notifier.notifyOtp("GitHub", "333333");
      expect(calls).toHaveLength(2);
    });
  });

  describe("Expiry alert rate limiting and behavior", () => {
    it("shows at most once per 6 hours per account, in code and hidden modes, skipped in off mode", async () => {
      const calls: Array<{ file: string; args: string[] }> = [];
      let mockTime = 1_000_000;

      const notifier = new DesktopNotifier({
        homeDir: tempDir,
        platform: "linux",
        now: () => mockTime,
        execFn: async (file, args) => {
          calls.push({ file, args });
        }
      });

      saveConfig({ notifications: "code" }, tempDir);

      // First alert for account 'personal'
      await notifier.notifyExpiry("personal");
      expect(calls).toHaveLength(1);
      expect(calls[0].args[7]).toBe("AutoOTP: Google access expired for personal");
      expect(calls[0].args[8]).toBe("Run: autootp login personal");

      // 1 hour later: still within 6 hours -> suppressed
      mockTime += 1 * 60 * 60 * 1000;
      await notifier.notifyExpiry("personal");
      expect(calls).toHaveLength(1);

      // Different account 'work' at same time -> triggers alert
      await notifier.notifyExpiry("work");
      expect(calls).toHaveLength(2);
      expect(calls[1].args[7]).toBe("AutoOTP: Google access expired for work");
      expect(calls[1].args[8]).toBe("Run: autootp login work");

      // 5 hours later (6 hours total since personal's first alert) -> personal triggers again
      mockTime += 5 * 60 * 60 * 1000;
      await notifier.notifyExpiry("personal");
      expect(calls).toHaveLength(3);

      // In 'hidden' mode, expiry alert still shows
      saveConfig({ notifications: "hidden" }, tempDir);
      mockTime += 6 * 60 * 60 * 1000;
      await notifier.notifyExpiry("personal");
      expect(calls).toHaveLength(4);
      expect(calls[3].args[7]).toBe("AutoOTP: Google access expired for personal");

      // In 'off' mode, expiry alert is skipped
      saveConfig({ notifications: "off" }, tempDir);
      mockTime += 6 * 60 * 60 * 1000;
      await notifier.notifyExpiry("personal");
      expect(calls).toHaveLength(4); // No new call
    });

    it("sanitizes account alias in expiry alert", async () => {
      const calls: Array<{ file: string; args: string[] }> = [];
      const notifier = new DesktopNotifier({
        homeDir: tempDir,
        platform: "linux",
        execFn: async (file, args) => {
          calls.push({ file, args });
        }
      });

      saveConfig({ notifications: "code" }, tempDir);
      await notifier.notifyExpiry("<b>evil-acc</b>");

      expect(calls).toHaveLength(1);
      expect(calls[0].args[7]).toBe("AutoOTP: Google access expired for b evil-acc /b");
      expect(calls[0].args[8]).toBe("Run: autootp login b evil-acc /b");
    });
  });
});
