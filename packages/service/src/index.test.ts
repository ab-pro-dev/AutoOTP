import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { WebSocket } from "ws";
import {
  TokenStore,
  saveConfig,
  getOrCreatePairToken
} from "@autootp/shared";
import { startService } from "./index.js";

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
      if (urlStr.includes("/messages?q=")) {
        if (!wsReady) {
          return new Response(JSON.stringify({ messages: [] }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
        return new Response(
          JSON.stringify({ messages: [{ id: "msg-service-42" }] }),
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
  });
});
