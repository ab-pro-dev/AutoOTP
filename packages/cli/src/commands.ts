import {
  TokenStore,
  getHomeDir,
  loadConfig,
  saveConfig,
  getOrCreatePairToken,
  HistoryStore,
  HistoryRetention,
  NotificationMode
} from "@autootp/shared";
import { loginWithBrowser, watchAccount, ReauthRequiredError } from "@autootp/gmail";
import { startService } from "@autootp/service";
import {
  validateAlias,
  validateExtensionId,
  checkCredentialsPermissions,
  openBrowser,
  formatAccountsTable,
  revokeToken,
  formatOtpNotification,
  formatHistoryTable,
  AccountEntry
} from "./utils.js";

export interface CommandContext {
  homeDir?: string;
  fetchImpl?: typeof fetch;
  signal?: AbortSignal;
  pollMs?: number;
  exitImpl?: (code: number) => void;
}

export async function loginAction(
  alias: string = "personal",
  context: CommandContext = {}
): Promise<void> {
  const homeDir = context.homeDir ?? getHomeDir();
  validateAlias(alias);

  const store = new TokenStore(homeDir);
  const existing = await store.get(alias);
  if (existing) {
    throw new Error(`Account "${alias}" already exists. Run: autootp remove ${alias}`);
  }

  checkCredentialsPermissions(homeDir);

  const result = await loginWithBrowser({
    accountId: alias,
    homeDir,
    fetchImpl: context.fetchImpl,
    onAuthUrl: (url) => {
      console.log("Authorize AutoOTP by opening this URL in your browser:\n");
      console.log(url + "\n");
      openBrowser(url);
    }
  });

  console.log(`Connected ${result.email} as '${alias}'`);
}

export async function accountsAction(context: CommandContext = {}): Promise<void> {
  const homeDir = context.homeDir ?? getHomeDir();
  const store = new TokenStore(homeDir);
  const aliases = await store.list();

  const entries: AccountEntry[] = [];
  for (const alias of aliases) {
    const data = await store.get(alias);
    if (data) {
      entries.push({
        alias,
        email: data.email,
        addedAt: data.addedAt
      });
    }
  }

  // Sort by addedAt ascending
  entries.sort((a, b) => a.addedAt - b.addedAt);

  console.log(formatAccountsTable(entries));
}

export async function removeAction(
  alias: string,
  context: CommandContext = {}
): Promise<void> {
  const homeDir = context.homeDir ?? getHomeDir();
  validateAlias(alias);

  const store = new TokenStore(homeDir);
  const existing = await store.get(alias);
  if (!existing) {
    throw new Error(`Account "${alias}" not found.`);
  }

  await store.remove(alias);

  const revoked = await revokeToken(existing.refreshToken, context.fetchImpl);
  console.log(
    `Removed account '${alias}'. Google token revoke: ${revoked ? "succeeded" : "failed"}.`
  );
}

export async function watchAction(context: CommandContext = {}): Promise<void> {
  const homeDir = context.homeDir ?? getHomeDir();
  const store = new TokenStore(homeDir);
  const aliases = await store.list();

  if (aliases.length === 0) {
    throw new Error("No accounts connected. Run: autootp login");
  }

  const abortController = new AbortController();
  const onParentAbort = () => {
    abortController.abort(context.signal?.reason);
  };

  if (context.signal) {
    if (context.signal.aborted) {
      abortController.abort(context.signal.reason);
    } else {
      context.signal.addEventListener("abort", onParentAbort, { once: true });
    }
  }

  const signal = abortController.signal;

  let sigintReceived = false;
  const onSigint = () => {
    sigintReceived = true;
    abortController.abort();
  };

  process.once("SIGINT", onSigint);

  try {
    const watcherPromises = aliases.map((alias) =>
      watchAccount({
        accountId: alias,
        homeDir,
        fetchImpl: context.fetchImpl,
        pollMs: context.pollMs,
        signal,
        onOtp: (otp) => {
          console.log(formatOtpNotification(otp));
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

    await Promise.all(watcherPromises);
  } finally {
    process.removeListener("SIGINT", onSigint);
    if (context.signal) {
      context.signal.removeEventListener("abort", onParentAbort);
    }
    if (sigintReceived) {
      process.exit(0);
    }
  }
}

export async function pairAction(
  extensionId: string,
  context: CommandContext = {}
): Promise<string> {
  validateExtensionId(extensionId);
  const homeDir = context.homeDir ?? getHomeDir();

  const config = loadConfig(homeDir);
  const origin = `chrome-extension://${extensionId}`;
  if (!config.allowedOrigins.includes(origin)) {
    config.allowedOrigins.push(origin);
    saveConfig(config, homeDir);
  }

  const token = getOrCreatePairToken(homeDir);
  console.log(token);
  console.log("Paste this token into the AutoOTP extension. Never share it.");
  return token;
}

export interface ServiceCommandOptions extends CommandContext {
  noWatch?: boolean;
  exitImpl?: (code: number) => void;
}

export async function serviceAction(
  options: ServiceCommandOptions = {}
): Promise<void> {
  await startService({
    noWatch: options.noWatch,
    homeDir: options.homeDir,
    fetchImpl: options.fetchImpl,
    signal: options.signal,
    exitImpl: options.exitImpl
  });
}

export async function configAction(context: CommandContext = {}): Promise<void> {
  const homeDir = context.homeDir ?? getHomeDir();
  const config = loadConfig(homeDir);
  console.log(`historyRetention: ${config.historyRetention}`);
  console.log(`notifications: ${config.notifications}`);
}

export async function configSetAction(
  key: string,
  value: string,
  context: CommandContext = {}
): Promise<void> {
  const exit = context.exitImpl ?? process.exit;
  const homeDir = context.homeDir ?? getHomeDir();

  if (key !== "historyRetention" && key !== "notifications") {
    console.error(
      `Unknown configuration key "${key}". Only "historyRetention" and "notifications" can be configured.`
    );
    exit(1);
    return;
  }

  if (key === "historyRetention") {
    if (value !== "off" && value !== "5m" && value !== "30m" && value !== "1h") {
      console.error(
        `Invalid value "${value}" for historyRetention. Valid values: off, 5m, 30m, 1h`
      );
      exit(1);
      return;
    }

    saveConfig({ historyRetention: value as HistoryRetention }, homeDir);
    console.log(`historyRetention: ${value}`);
    return;
  }

  if (key === "notifications") {
    if (value !== "off" && value !== "hidden" && value !== "code") {
      console.error(
        `Invalid value "${value}" for notifications. Valid values: off, hidden, code`
      );
      exit(1);
      return;
    }

    saveConfig({ notifications: value as NotificationMode }, homeDir);
    console.log(`notifications: ${value}`);
    return;
  }
}

export async function historyAction(context: CommandContext = {}): Promise<void> {
  const homeDir = context.homeDir ?? getHomeDir();
  const store = new HistoryStore(homeDir);
  try {
    const entries = store.list();
    if (entries.length === 0) {
      console.log("No history.");
      return;
    }
    console.log(formatHistoryTable(entries));
  } finally {
    store.close();
  }
}

export async function clearAction(context: CommandContext = {}): Promise<void> {
  const homeDir = context.homeDir ?? getHomeDir();
  const store = new HistoryStore(homeDir);
  try {
    const count = store.clear();
    console.log(`Cleared ${count} ${count === 1 ? "row" : "rows"} from history.`);
  } finally {
    store.close();
  }
}

export * from "./autostart.js";



