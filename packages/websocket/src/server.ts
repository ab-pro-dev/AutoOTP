import http from "node:http";
import crypto from "node:crypto";
import { AddressInfo, Socket } from "node:net";
import { WebSocket, WebSocketServer } from "ws";

export interface CreateOtpServerOptions {
  port?: number;
  token: string;
  allowedOrigins: string[];
  allowNoOrigin?: boolean;
  authTimeoutMs?: number;
  pingIntervalMs?: number;
  onClientCountChange?: (count: number) => void;
}

export interface OtpBroadcastPayload {
  id?: string;
  sender: string;
  senderDomain?: string | null;
  code: string;
  raw: string;
  account: string;
  receivedAt?: number;
}

export interface OtpServer {
  broadcastOtp: (otp: OtpBroadcastPayload) => void;
  clientCount: () => number;
  close: () => Promise<void>;
  port: number;
}

function rejectUpgrade(
  socket: import("node:stream").Duplex,
  statusCode: number = 403,
  statusText: string = "Forbidden"
): void {
  if (socket.writable) {
    socket.write(
      `HTTP/1.1 ${statusCode} ${statusText}\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\n${statusText}`
    );
  }
  socket.destroy();
}

/**
 * Creates and starts a secure local OTP WebSocket server.
 * Binds strictly to 127.0.0.1.
 */
export async function createOtpServer(
  options: CreateOtpServerOptions
): Promise<OtpServer> {
  const {
    port = 47821,
    token,
    allowedOrigins,
    allowNoOrigin = false,
    authTimeoutMs = 3000,
    pingIntervalMs = 20000
  } = options;

  if (!token || typeof token !== "string") {
    throw new Error("A valid authentication token is required");
  }

  const expectedTokenBuf = Buffer.from(token, "utf8");

  const httpServer = http.createServer((_req, res) => {
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("Not Found");
  });

  const wss = new WebSocketServer({
    noServer: true,
    maxPayload: 4096
  });

  const activeSockets = new Set<WebSocket>();
  const authenticatedSockets = new Set<WebSocket>();

  const notifyClientCount = () => {
    options.onClientCountChange?.(authenticatedSockets.size);
  };

  let boundPort = port;

  httpServer.on("upgrade", (req, socket, head) => {
    // 1. Origin header verification
    const origin = req.headers.origin;
    if (!origin) {
      if (!allowNoOrigin) {
        rejectUpgrade(socket, 403, "Forbidden");
        return;
      }
    } else {
      if (!allowedOrigins.includes(origin)) {
        rejectUpgrade(socket, 403, "Forbidden");
        return;
      }
    }

    // 2. Host header verification (DNS rebinding protection)
    const host = req.headers.host?.toLowerCase();
    const allowedHosts = [`127.0.0.1:${boundPort}`, `localhost:${boundPort}`];
    if (boundPort === 80) {
      allowedHosts.push("127.0.0.1", "localhost");
    }
    if (!host || !allowedHosts.includes(host)) {
      rejectUpgrade(socket, 403, "Forbidden");
      return;
    }

    // 3. Maximum 5 simultaneous connections limit
    if (activeSockets.size >= 5) {
      rejectUpgrade(socket, 403, "Forbidden");
      return;
    }

    wss.handleUpgrade(req, socket, head, (ws) => {
      wss.emit("connection", ws, req);
    });
  });

  wss.on("connection", (ws: WebSocket) => {
    activeSockets.add(ws);
    let authenticated = false;

    const authTimer = setTimeout(() => {
      if (!authenticated) {
        ws.close(4401, "Unauthorized");
      }
    }, authTimeoutMs);

    ws.on("error", () => {
      clearTimeout(authTimer);
      activeSockets.delete(ws);
      if (authenticatedSockets.delete(ws)) {
        notifyClientCount();
      }
    });

    ws.on("close", () => {
      clearTimeout(authTimer);
      activeSockets.delete(ws);
      if (authenticatedSockets.delete(ws)) {
        notifyClientCount();
      }
    });

    ws.on("message", (raw: WebSocket.RawData) => {
      let text: string;
      if (typeof raw === "string") {
        text = raw;
      } else if (Buffer.isBuffer(raw)) {
        text = raw.toString("utf8");
      } else if (Array.isArray(raw)) {
        text = Buffer.concat(raw).toString("utf8");
      } else {
        text = Buffer.from(raw).toString("utf8");
      }

      let parsed: any;
      try {
        parsed = JSON.parse(text);
      } catch {
        ws.close(1008, "Invalid JSON");
        return;
      }

      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        ws.close(1008, "Invalid payload");
        return;
      }

      if (!authenticated) {
        if (parsed.type !== "auth" || typeof parsed.token !== "string") {
          clearTimeout(authTimer);
          ws.close(4401, "Unauthorized");
          return;
        }

        const clientBuf = Buffer.from(parsed.token, "utf8");
        const isMatch =
          clientBuf.length === expectedTokenBuf.length &&
          crypto.timingSafeEqual(clientBuf, expectedTokenBuf);

        if (!isMatch) {
          clearTimeout(authTimer);
          ws.close(4401, "Unauthorized");
          return;
        }

        authenticated = true;
        clearTimeout(authTimer);
        authenticatedSockets.add(ws);
        notifyClientCount();
        ws.send(JSON.stringify({ type: "hello", version: 1 }));
        return;
      }

      // Authenticated message handling
      if (parsed.type === "pong") {
        return;
      }

      ws.close(1008, "Unknown message type");
    });
  });

  const pingInterval = setInterval(() => {
    const pingMsg = JSON.stringify({ type: "ping" });
    for (const client of authenticatedSockets) {
      if (client.readyState === WebSocket.OPEN) {
        client.send(pingMsg);
      }
    }
  }, pingIntervalMs);
  pingInterval.unref?.();

  await new Promise<void>((resolve, reject) => {
    httpServer.listen(port, "127.0.0.1", () => {
      const addr = httpServer.address() as AddressInfo;
      boundPort = addr.port;
      resolve();
    });
    httpServer.once("error", reject);
  });

  const broadcastOtp = (otp: OtpBroadcastPayload): void => {
    const msg: Record<string, unknown> = {
      type: "otp",
      id: otp.id ?? crypto.randomUUID(),
      sender: otp.sender,
      code: otp.code,
      raw: otp.raw,
      account: otp.account,
      receivedAt: otp.receivedAt ?? Date.now()
    };
    if (otp.senderDomain !== undefined) {
      msg.senderDomain = otp.senderDomain;
    }
    const payload = JSON.stringify(msg);

    for (const client of authenticatedSockets) {
      if (client.readyState === WebSocket.OPEN) {
        client.send(payload);
      }
    }
  };

  const clientCount = (): number => {
    return authenticatedSockets.size;
  };

  const close = async (): Promise<void> => {
    clearInterval(pingInterval);

    for (const client of activeSockets) {
      client.terminate();
    }
    const hadAuthed = authenticatedSockets.size > 0;
    activeSockets.clear();
    authenticatedSockets.clear();
    if (hadAuthed) {
      notifyClientCount();
    }

    await new Promise<void>((resolve) => {
      wss.close(() => resolve());
    });

    if (typeof (httpServer as any).closeAllConnections === "function") {
      (httpServer as any).closeAllConnections();
    }

    await new Promise<void>((resolve, reject) => {
      httpServer.close((err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  };

  return {
    broadcastOtp,
    clientCount,
    close,
    port: boundPort
  };
}
