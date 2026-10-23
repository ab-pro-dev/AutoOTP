import crypto from "node:crypto";
import process from "node:process";
import {
  getHomeDir,
  loadConfig,
  getOrCreatePairToken,
  TokenStore,
  formatOtpNotification,
  ConfigurationError,
  AutoOtpConfig,
  HistoryStore,
  writeStatus,
  deleteStatus,
  AccountStatus,
  StatusLastOtp,
  VERSION
} from "@autootp/shared";
import { watchAccount, ReauthRequiredError } from "@autootp/gmail";
import { createOtpServer, OtpServer } from "@autootp/websocket";
import { DesktopNotifier, ExecFunction } from "./notifier.js";

export interface StartServiceOptions {
  noWatch?: boolean;
  homeDir?: string;
  fetchImpl?: typeof fetch;
  signal?: AbortSignal;
  exitImpl?: (code: number) => void;
  onStarted?: (info: { port: number; server: OtpServer }) => void | Promise<void>;
  config?: AutoOtpConfig;
  token?: string;
  historyStore?: HistoryStore;
  execFn?: ExecFunction;
  platform?: NodeJS.Platform;
  now?: () => number;
  notifier?: DesktopNotifier;
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
      options.exitImpl(78);
      return;
    }
    throw new ConfigurationError(msg);
  }

  const store = new TokenStore(homeDir);
  let aliases: string[] = [];
  if (!options.noWatch) {
    aliases = await store.list();
    if (aliases.length === 0) {
      const msg = "No accounts connected. Run: autootp login";
      if (options.exitImpl) {
        console.error(msg);
        options.exitImpl(78);
        return;
      }
      throw new ConfigurationError(msg);
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

  const notifier =
    options.notifier ??
    new DesktopNotifier({
      homeDir,
      platform: options.platform,
      execFn: options.execFn,
      now: options.now,
      config
    });

  let historyStore: HistoryStore | null = null;
  try {
    historyStore = options.historyStore ?? new HistoryStore(homeDir);
    historyStore.purge();
  } catch {
    // Wrap history errors so they can never stop OTP delivery
  }

  const purgeInterval = setInterval(() => {
    try {
      historyStore?.purge();
    } catch {
      // Wrap history errors so they can never stop OTP delivery
    }
  }, 60000);
  if (purgeInterval.unref) {
    purgeInterval.unref();
  }

  const startedAt = Date.now();
  const accountsStatus: Record<string, AccountStatus> = {};
  const failureCounts = new Map<string, number>();
  for (const alias of aliases) {
    accountsStatus[alias] = "ok";
  }
  let lastOtp: StatusLastOtp | null = null;
  let authedClients = 0;

  let server: OtpServer;

  const syncStatus = () => {
    try {
      writeStatus(
        {
          v: 1,
          pid: process.pid,
          version: VERSION,
          startedAt,
          updatedAt: Date.now(),
          port: server?.port ?? config.port,
          authedClients,
          accounts: { ...accountsStatus },
          lastOtp
        },
        homeDir
      );
    } catch {
      // Never crash on status write
    }
  };

  try {
    server = await createOtpServer({
      port: config.port,
      token,
      allowedOrigins: config.allowedOrigins,
      onClientCountChange: (count) => {
        authedClients = count;
        syncStatus();
      }
    });
    syncStatus();
  } catch (err: unknown) {
    clearInterval(purgeInterval);
    try {
      historyStore?.close();
    } catch {}
    deleteStatus(homeDir);
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

  const heartbeatInterval = setInterval(() => {
    syncStatus();
  }, 30000);
  if (heartbeatInterval.unref) {
    heartbeatInterval.unref();
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
          onPollSuccess: () => {
            failureCounts.set(alias, 0);
            if (accountsStatus[alias] !== "ok") {
              accountsStatus[alias] = "ok";
              syncStatus();
            }
          },
          onOtp: async (otp) => {
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

            // Update status on OTP
            lastOtp = {
              sender: otp.sender,
              senderDomain: otp.senderDomain ?? null,
              at: otp.receivedAt ?? Date.now()
            };
            failureCounts.set(alias, 0);
            if (accountsStatus[alias] !== "ok") {
              accountsStatus[alias] = "ok";
            }
            syncStatus();

            // Send desktop notification
            try {
              await notifier.notifyOtp(otp.sender, otp.code);
            } catch {
              // Failures of the notification command are caught and ignored
            }

            // Add to history and purge
            try {
              if (historyStore) {
                historyStore.add({
                  sender: otp.sender,
                  senderDomain: otp.senderDomain,
                  alias,
                  code: otp.code,
                  receivedAt: otp.receivedAt
                });
                historyStore.purge();
              }
            } catch {
              // Wrap history errors so they can never stop OTP delivery
            }
          },
          onError: async (err) => {
            if (
              err instanceof ReauthRequiredError ||
              err.name === "ReauthRequiredError"
            ) {
              console.log(
                `${alias}: Google access expired. Run: autootp login ${alias} again.`
              );
              accountsStatus[alias] = "expired";
              syncStatus();
              try {
                await notifier.notifyExpiry(alias);
              } catch {
                // Failures of the notification command are caught and ignored
              }
            } else {
              const count = (failureCounts.get(alias) ?? 0) + 1;
              failureCounts.set(alias, count);
              if (count >= 3 && accountsStatus[alias] !== "error") {
                accountsStatus[alias] = "error";
                syncStatus();
              }
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
    clearInterval(purgeInterval);
    clearInterval(heartbeatInterval);
    deleteStatus(homeDir);
    try {
      historyStore?.close();
    } catch {}
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
