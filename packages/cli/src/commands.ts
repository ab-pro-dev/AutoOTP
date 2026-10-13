import { TokenStore, getHomeDir } from "@autootp/shared";
import { loginWithBrowser } from "@autootp/gmail";
import {
  validateAlias,
  checkCredentialsPermissions,
  openBrowser,
  formatAccountsTable,
  revokeToken,
  AccountEntry
} from "./utils.js";

export interface CommandContext {
  homeDir?: string;
  fetchImpl?: typeof fetch;
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
