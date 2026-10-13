import { TokenStore, getHomeDir } from "@autootp/shared";
import { loginWithBrowser, watchAccount, ReauthRequiredError } from "@autootp/gmail";
import {
  validateAlias,
  checkCredentialsPermissions,
  openBrowser,
  formatAccountsTable,
  revokeToken,
  formatOtpNotification,
  AccountEntry
} from "./utils.js";

export interface CommandContext {
  homeDir?: string;
  fetchImpl?: typeof fetch;
  signal?: AbortSignal;
  pollMs?: number;
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

