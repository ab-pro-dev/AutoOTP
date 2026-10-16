import net from "node:net";
import { describe, it, expect } from "vitest";
import { WebSocket } from "ws";
import { createOtpServer, OtpServer } from "./index.js";

function waitForOpen(ws: WebSocket): Promise<void> {
  return new Promise((resolve, reject) => {
    ws.on("open", resolve);
    ws.on("error", reject);
  });
}

function waitForClose(ws: WebSocket): Promise<{ code: number; reason: string }> {
  return new Promise((resolve) => {
    ws.on("close", (code, reason) => {
      resolve({ code, reason: reason.toString() });
    });
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

describe("Local OTP WebSocket Server (packages/websocket)", () => {
  it("the server listens on 127.0.0.1 (check server address)", async () => {
    const server = await createOtpServer({
      port: 0,
      token: "valid-token-123",
      allowedOrigins: ["chrome-extension://my-extension-id"]
    });

    try {
      expect(server.port).toBeGreaterThan(0);

      // Verify connection to 127.0.0.1 succeeds
      await new Promise<void>((resolve, reject) => {
        const socket = net.connect(server.port, "127.0.0.1", () => {
          socket.end();
          resolve();
        });
        socket.on("error", reject);
      });
    } finally {
      await server.close();
    }
  });

  it("a valid auth receives hello and then an otp broadcast", async () => {
    const server = await createOtpServer({
      port: 0,
      token: "secret-token-abc",
      allowedOrigins: ["chrome-extension://my-extension-id"]
    });

    const client = new WebSocket(`ws://127.0.0.1:${server.port}`, {
      headers: { Origin: "chrome-extension://my-extension-id" }
    });

    try {
      await waitForOpen(client);

      const helloPromise = waitForMessage(client);
      client.send(JSON.stringify({ type: "auth", token: "secret-token-abc" }));

      const hello = await helloPromise;
      expect(hello).toEqual({ type: "hello", version: 1 });
      expect(server.clientCount()).toBe(1);

      const otpPromise = waitForMessage(client);
      server.broadcastOtp({
        id: "msg-1",
        sender: "GitHub",
        code: "482910",
        raw: "Your code is 482910",
        account: "personal",
        receivedAt: 1700000000000
      });

      const otpMsg = await otpPromise;
      expect(otpMsg).toEqual({
        type: "otp",
        id: "msg-1",
        sender: "GitHub",
        code: "482910",
        raw: "Your code is 482910",
        account: "personal",
        receivedAt: 1700000000000
      });

      // Broadcast with senderDomain present
      const otpWithDomainPromise = waitForMessage(client);
      server.broadcastOtp({
        id: "msg-2",
        sender: "GitHub",
        senderDomain: "github.com",
        code: "123456",
        raw: "Your code is 123456",
        account: "personal",
        receivedAt: 1700000000000
      });
      const otpWithDomain = await otpWithDomainPromise;
      expect(otpWithDomain).toEqual({
        type: "otp",
        id: "msg-2",
        sender: "GitHub",
        senderDomain: "github.com",
        code: "123456",
        raw: "Your code is 123456",
        account: "personal",
        receivedAt: 1700000000000
      });
    } finally {
      client.close();
      await server.close();
    }
  });

  it("a wrong token is closed with 4401 and receives nothing", async () => {
    const server = await createOtpServer({
      port: 0,
      token: "correct-secret-token",
      allowedOrigins: ["chrome-extension://my-extension-id"]
    });

    const client = new WebSocket(`ws://127.0.0.1:${server.port}`, {
      headers: { Origin: "chrome-extension://my-extension-id" }
    });

    try {
      await waitForOpen(client);

      let receivedMessages = 0;
      client.on("message", () => {
        receivedMessages++;
      });

      const closePromise = waitForClose(client);
      client.send(JSON.stringify({ type: "auth", token: "wrong-token" }));

      const { code } = await closePromise;
      expect(code).toBe(4401);
      expect(receivedMessages).toBe(0);
      expect(server.clientCount()).toBe(0);
    } finally {
      client.close();
      await server.close();
    }
  });

  it("an unauthenticated client gets no broadcast and is closed after the timeout (use a short test timeout option)", async () => {
    const server = await createOtpServer({
      port: 0,
      token: "auth-timeout-token",
      allowedOrigins: ["chrome-extension://my-extension-id"],
      authTimeoutMs: 50
    });

    const client = new WebSocket(`ws://127.0.0.1:${server.port}`, {
      headers: { Origin: "chrome-extension://my-extension-id" }
    });

    try {
      await waitForOpen(client);

      let receivedMessages = 0;
      client.on("message", () => {
        receivedMessages++;
      });

      const closePromise = waitForClose(client);

      // Broadcast while client is unauthenticated
      server.broadcastOtp({
        sender: "Stripe",
        code: "999888",
        raw: "999888",
        account: "work"
      });

      const { code } = await closePromise;
      expect(code).toBe(4401);
      expect(receivedMessages).toBe(0);
    } finally {
      client.close();
      await server.close();
    }
  });

  it("a bad Origin is rejected with 403, a bad Host is rejected, and a 6th connection is rejected", async () => {
    const server = await createOtpServer({
      port: 0,
      token: "conn-limits-token",
      allowedOrigins: ["chrome-extension://allowed-id"]
    });

    try {
      // 1. Bad Origin rejected with 403
      const badOriginStatus = await new Promise<number>((resolve) => {
        const ws = new WebSocket(`ws://127.0.0.1:${server.port}`, {
          headers: { Origin: "https://evil-attacker.com" }
        });
        ws.on("unexpected-response", (_req, res) => {
          resolve(res.statusCode ?? 0);
        });
        ws.on("error", () => {});
      });
      expect(badOriginStatus).toBe(403);

      // Missing Origin rejected with 403 (when allowNoOrigin is false)
      const missingOriginStatus = await new Promise<number>((resolve) => {
        const ws = new WebSocket(`ws://127.0.0.1:${server.port}`);
        ws.on("unexpected-response", (_req, res) => {
          resolve(res.statusCode ?? 0);
        });
        ws.on("error", () => {});
      });
      expect(missingOriginStatus).toBe(403);

      // 2. Bad Host rejected with 403
      const badHostStatus = await new Promise<number>((resolve) => {
        const ws = new WebSocket(`ws://127.0.0.1:${server.port}`, {
          headers: {
            Origin: "chrome-extension://allowed-id",
            Host: "evil-dns-rebind.com"
          }
        });
        ws.on("unexpected-response", (_req, res) => {
          resolve(res.statusCode ?? 0);
        });
        ws.on("error", () => {});
      });
      expect(badHostStatus).toBe(403);

      // 3. Connect 5 clients
      const clients: WebSocket[] = [];
      for (let i = 0; i < 5; i++) {
        const ws = new WebSocket(`ws://127.0.0.1:${server.port}`, {
          headers: { Origin: "chrome-extension://allowed-id" }
        });
        await waitForOpen(ws);
        clients.push(ws);
      }

      // Try 6th connection -> must be rejected with 403
      const sixthStatus = await new Promise<number>((resolve) => {
        const ws = new WebSocket(`ws://127.0.0.1:${server.port}`, {
          headers: { Origin: "chrome-extension://allowed-id" }
        });
        ws.on("unexpected-response", (_req, res) => {
          resolve(res.statusCode ?? 0);
        });
        ws.on("error", () => {});
      });
      expect(sixthStatus).toBe(403);

      for (const ws of clients) {
        ws.close();
      }
    } finally {
      await server.close();
    }
  });

  it("an oversized message closes the connection", async () => {
    const server = await createOtpServer({
      port: 0,
      token: "payload-token",
      allowedOrigins: ["chrome-extension://allowed-id"]
    });

    const client = new WebSocket(`ws://127.0.0.1:${server.port}`, {
      headers: { Origin: "chrome-extension://allowed-id" }
    });

    try {
      await waitForOpen(client);
      const closePromise = waitForClose(client);

      // Send 5000 bytes message (> 4096 bytes maxPayload)
      client.send("X".repeat(5000));

      const { code } = await closePromise;
      expect(code).toBe(1009); // Message Too Big
    } finally {
      client.close();
      await server.close();
    }
  });

  it("close() disconnects everyone and frees the port", async () => {
    const server = await createOtpServer({
      port: 0,
      token: "close-test-token",
      allowedOrigins: ["chrome-extension://allowed-id"]
    });

    const port = server.port;
    const client = new WebSocket(`ws://127.0.0.1:${port}`, {
      headers: { Origin: "chrome-extension://allowed-id" }
    });

    await waitForOpen(client);
    client.send(JSON.stringify({ type: "auth", token: "close-test-token" }));
    await waitForMessage(client);

    const closePromise = waitForClose(client);
    await server.close();

    // Client should be disconnected
    await closePromise;
    expect(client.readyState).toBe(WebSocket.CLOSED);

    // Port should be freed (new connection fails)
    await expect(
      new Promise((resolve, reject) => {
        const socket = net.connect(port, "127.0.0.1", () => {
          socket.end();
          resolve(true);
        });
        socket.on("error", reject);
      })
    ).rejects.toThrow();
  });

  it("ping, pong and invalid message handling", async () => {
    const server = await createOtpServer({
      port: 0,
      token: "ping-test-token",
      allowedOrigins: ["chrome-extension://allowed-id"],
      pingIntervalMs: 25
    });

    const client = new WebSocket(`ws://127.0.0.1:${server.port}`, {
      headers: { Origin: "chrome-extension://allowed-id" }
    });

    try {
      await waitForOpen(client);
      client.send(JSON.stringify({ type: "auth", token: "ping-test-token" }));
      const hello = await waitForMessage(client);
      expect(hello.type).toBe("hello");

      // Wait for server-initiated application ping
      const pingMsg = await waitForMessage(client);
      expect(pingMsg).toEqual({ type: "ping" });

      // Send pong
      client.send(JSON.stringify({ type: "pong" }));

      // Unknown message type closes with 1008
      const closePromise = waitForClose(client);
      client.send(JSON.stringify({ type: "unknown_type" }));
      const { code } = await closePromise;
      expect(code).toBe(1008);
    } finally {
      client.close();
      await server.close();
    }
  });
});
