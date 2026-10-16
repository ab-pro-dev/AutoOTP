import crypto from "node:crypto";
import process from "node:process";
import {
  getHomeDir,
  loadConfig,
  getOrCreatePairToken,
  TokenStore,
  formatOtpNotification,
  AutoOtpConfig
} from "@autootp/shared";
import { watchAccount, ReauthRequiredError } from "@autootp/gmail";
import { createOtpServer, OtpServer } from "@autootp/websocket";

export interface StartServiceOptions {
  noWatch?: boolean;
  homeDir?: string;
  fetchImpl?: typeof fetch;
  signal?: AbortSignal;
  exitImpl?: (code: number) => void;
  onStarted?: (info: { port: number; server: OtpServer }) => void | Promise<void>;
  config?: AutoOtpConfig;
  token?: string;
}

/**
 * Starts the AutoOTP background service:
 * - Loads pairing token and configuration
 * - Starts the secure local WebSocket server
 * - Optionally starts Gmail watchers for all connected accounts and broadcasts incoming OTPs
 */
export async function startService(options: StartServiceOptions = {}): Promise<void> {
  const homeDir = options.homeDir ?? getHomeDir();
  const config = options.config ?? loadConfig(homeDir);
  const token = options.token ?? getOrCreatePairToken(homeDir);

  if (!config.allowedOrigins || config.allowedOrigins.length === 0) {
    const msg = "No extension paired. Run: autootp pair <extensionId>";
    if (options.exitImpl) {
      console.error(msg);
      options.exitImpl(1);
      return;
    }
    throw new Error(msg);
  }

  const store = new TokenStore(homeDir);
  let aliases: string[] = [];
  if (!options.noWatch) {
    aliases = await store.list();
    if (aliases.length === 0) {
      const msg = "No accounts connected. Run: autootp login";
      if (options.exitImpl) {
        console.error(msg);
        options.exitImpl(1);
        return;
      }
      throw new Error(msg);
    }
  }

  const abortController = new AbortController();
  const onParentAbort = () => {
    abortController.abort(options.signal?.reason);
  };

  if (options.signal) {
    if (options.signal.aborted) {
      abortController.abort(options.signal.reason);
    } else {
      options.signal.addEventListener("abort", onParentAbort, { once: true });
    }
  }

  const signal = abortController.signal;

  let sigintReceived = false;
  const onSigint = () => {
    sigintReceived = true;
    abortController.abort();
  };

  process.once("SIGINT", onSigint);

  let server: OtpServer;
  try {
    server = await createOtpServer({
      port: config.port,
      token,
      allowedOrigins: config.allowedOrigins
    });
  } catch (err: unknown) {
    process.removeListener("SIGINT", onSigint);
    if (options.signal) {
      options.signal.removeEventListener("abort", onParentAbort);
    }
    const error = err as NodeJS.ErrnoException;
    if (error?.code === "EADDRINUSE" || error?.message?.includes("EADDRINUSE")) {
      const msg = `Port ${config.port} in use. Is AutoOTP already running?`;
      if (options.exitImpl) {
        console.error(msg);
        options.exitImpl(1);
        return;
      }
      const customErr = new Error(msg);
      (customErr as any).code = "EADDRINUSE";
      throw customErr;
    }
    throw err;
  }

  const watcherPromises: Promise<void>[] = [];
  if (!options.noWatch) {
    for (const alias of aliases) {
      watcherPromises.push(
        watchAccount({
          accountId: alias,
          homeDir,
          pollMs: config.pollMs,
          signal,
          fetchImpl: options.fetchImpl,
          onOtp: (otp) => {
            // Broadcast to authenticated WebSocket clients
            server.broadcastOtp({
              id: otp.messageId ?? otp.id ?? crypto.randomUUID(),
              sender: otp.sender,
              senderDomain: otp.senderDomain,
              code: otp.code,
              raw: otp.raw,
              account: alias,
              receivedAt: otp.receivedAt
            });
            // Print with existing terminal format
            console.log(
              formatOtpNotification({
                accountId: alias,
                sender: otp.sender,
                code: otp.code,
                receivedAt: otp.receivedAt
              })
            );
          },
          onError: (err) => {
            if (
              err instanceof ReauthRequiredError ||
              err.name === "ReauthRequiredError"
            ) {
              console.log(
                `${alias}: Google access expired. Run: autootp login ${alias} again.`
              );
            }
          }
        })
      );
    }
  }

  if (options.onStarted) {
    try {
      await options.onStarted({ port: server.port, server });
    } catch (startErr) {
      abortController.abort(startErr);
      await server.close().catch(() => {});
      throw startErr;
    }
  }

  let abortCleanup: (() => void) | undefined;
  const abortPromise = new Promise<void>((resolve) => {
    if (signal.aborted) return resolve();
    const onAbort = () => {
      cleanup();
      resolve();
    };
    const cleanup = () => {
      signal.removeEventListener("abort", onAbort);
    };
    abortCleanup = cleanup;
    signal.addEventListener("abort", onAbort, { once: true });
  });

  try {
    await Promise.all([abortPromise, ...watcherPromises]);
  } finally {
    abortCleanup?.();
    process.removeListener("SIGINT", onSigint);
    if (options.signal) {
      options.signal.removeEventListener("abort", onParentAbort);
    }
    await server.close().catch(() => {});
    if (sigintReceived) {
      process.exit(0);
    }
  }
}
