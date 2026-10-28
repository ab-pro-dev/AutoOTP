import readline from "node:readline/promises";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  getHomeDir,
  loadConfig,
  saveConfig,
  getOrCreatePairToken,
  TokenStore
} from "@autootp/shared";
import {
  CommandContext,
  loginAction,
  enableAction,
  doctorAction
} from "./commands.js";
import { resolveExtensionPath, getExtensionId } from "./extension-path.js";
import { validateAlias } from "./utils.js";

export interface SetupContext extends CommandContext {
  input?: NodeJS.ReadableStream;
  output?: NodeJS.WritableStream;
  isTTY?: boolean;
  platform?: NodeJS.Platform;
  downloadsDir?: string;
  loginFn?: (alias: string, context: CommandContext) => Promise<void>;
  enableFn?: (context: CommandContext) => Promise<void>;
  doctorFn?: (context: CommandContext) => Promise<void>;
  nodeVersion?: string;
  unitDir?: string;
}

export function isNodeSupported(version: string): boolean {
  const cleanVer = version.replace(/^v/, "");
  const [major, minor] = cleanVer.split(".").map((n) => parseInt(n, 10));
  return major > 22 || (major === 22 && minor >= 13);
}

export function validateCredentialsFile(filePath: string): { ok: boolean; error?: string; raw?: string } {
  if (!fs.existsSync(filePath)) {
    return { ok: false, error: `File not found: ${filePath}` };
  }
  let raw: string;
  try {
    raw = fs.readFileSync(filePath, "utf8");
  } catch (err: any) {
    return { ok: false, error: `Cannot read file: ${err.message}` };
  }
  let data: any;
  try {
    data = JSON.parse(raw);
  } catch {
    return { ok: false, error: "File contains invalid JSON" };
  }
  if (!data || typeof data !== "object") {
    return { ok: false, error: "JSON must be an object" };
  }
  if (!data.installed || typeof data.installed !== "object") {
    return { ok: false, error: 'Missing "installed" object in credentials JSON' };
  }
  const { client_id, client_secret } = data.installed;
  if (!client_id || typeof client_id !== "string" || !client_secret || typeof client_secret !== "string") {
    return { ok: false, error: '"installed" object must contain "client_id" and "client_secret"' };
  }
  return { ok: true, raw };
}

export function isCredentialsValid(homeDir: string): boolean {
  const credPath = path.join(homeDir, "credentials.json");
  if (!fs.existsSync(credPath)) return false;
  return validateCredentialsFile(credPath).ok;
}

export async function getConnectedAccountsCount(homeDir: string): Promise<number> {
  const tokensPath = path.join(homeDir, "tokens.enc");
  if (!fs.existsSync(tokensPath)) return 0;
  try {
    const store = new TokenStore(homeDir);
    const list = await store.list();
    return list.length;
  } catch {
    return 0;
  }
}

export function isExtensionPaired(homeDir: string, extId: string): boolean {
  const configPath = path.join(homeDir, "config.json");
  if (!fs.existsSync(configPath)) return false;
  try {
    const config = loadConfig(homeDir);
    return (
      Array.isArray(config.allowedOrigins) &&
      config.allowedOrigins.includes(`chrome-extension://${extId}`)
    );
  } catch {
    return false;
  }
}

export function isAutoStartDone(context: SetupContext): boolean {
  const platform = context.platform ?? process.platform;
  if (platform !== "linux") {
    return false;
  }
  const unitDir = context.unitDir ?? path.join(os.homedir(), ".config", "systemd", "user");
  const unitPath = path.join(unitDir, "autootp.service");
  if (!fs.existsSync(unitPath)) {
    return false;
  }
  const autootpHome = context.homeDir ?? process.env.AUTOOTP_HOME;
  const defaultHome = path.join(os.homedir(), ".autootp");
  if (autootpHome && path.resolve(autootpHome) !== path.resolve(defaultHome)) {
    try {
      const content = fs.readFileSync(unitPath, "utf8");
      return content.includes(`AUTOOTP_HOME=${autootpHome}`);
    } catch {
      return false;
    }
  }
  return true;
}

export function findNewestDownloadedCredentials(downloadsDir: string): string | null {
  if (!fs.existsSync(downloadsDir)) return null;
  try {
    const files = fs.readdirSync(downloadsDir);
    const matches: { path: string; mtime: number }[] = [];
    for (const file of files) {
      if (file.startsWith("client_secret_") && file.endsWith(".json")) {
        const fullPath = path.join(downloadsDir, file);
        try {
          const stat = fs.statSync(fullPath);
          if (stat.isFile()) {
            matches.push({ path: fullPath, mtime: stat.mtimeMs });
          }
        } catch {}
      }
    }
    if (matches.length === 0) return null;
    matches.sort((a, b) => b.mtime - a.mtime);
    return matches[0].path;
  } catch {
    return null;
  }
}

class SetupPrompter {
  private rl: readline.Interface;
  private ac = new AbortController();
  private closed = false;

  constructor(input: NodeJS.ReadableStream, output: NodeJS.WritableStream) {
    this.rl = readline.createInterface({ input, output });

    const handleCancel = () => {
      this.closed = true;
      if (!this.ac.signal.aborted) {
        this.ac.abort(new Error("Setup cancelled"));
      }
    };

    this.rl.on("close", handleCancel);
    this.rl.on("SIGINT", handleCancel);
    input.on("end", handleCancel);
  }

  async ask(promptText: string): Promise<string> {
    if (this.closed || this.ac.signal.aborted) {
      throw new Error("Setup cancelled");
    }
    try {
      return await this.rl.question(promptText, { signal: this.ac.signal });
    } catch {
      throw new Error("Setup cancelled");
    }
  }

  close() {
    this.closed = true;
    this.rl.close();
  }
}

export async function setupAction(
  opts: { dryRun?: boolean },
  context: SetupContext = {}
): Promise<void> {
  const homeDir = context.homeDir ?? getHomeDir();
  const exit = context.exitImpl ?? process.exit;
  const input = context.input ?? process.stdin;
  const output = context.output ?? process.stdout;
  const isTTY = context.isTTY !== undefined ? context.isTTY : Boolean((input as any).isTTY);

  const print = (msg: string = "") => {
    if (context.output && context.output !== process.stdout) {
      context.output.write(msg + "\n");
    } else {
      console.log(msg);
    }
  };

  const printError = (msg: string) => {
    if (context.output && context.output !== process.stdout) {
      context.output.write(msg + "\n");
    } else {
      console.error(msg);
    }
  };

  // If stdin is not a TTY, print "Setup needs an interactive terminal." and exit 1.
  if (!opts.dryRun && !isTTY) {
    printError("Setup needs an interactive terminal.");
    exit(1);
    return;
  }

  const getExtId = () => {
    try {
      return getExtensionId(context.metaUrl ?? import.meta.url);
    } catch {
      return "";
    }
  };

  // --dry-run prints the status of every step as "done" or "todo" and changes nothing.
  if (opts.dryRun) {
    const step1 = isNodeSupported(context.nodeVersion ?? process.versions.node);
    const step2 = isCredentialsValid(homeDir);
    const step3 = (await getConnectedAccountsCount(homeDir)) > 0;
    const extId = getExtId();
    const step4 = extId ? isExtensionPaired(homeDir, extId) : false;
    const step5 = isAutoStartDone(context);
    const step6 =
      step1 &&
      step2 &&
      step3 &&
      step4 &&
      step5 &&
      (context.doctorFn
        ? true
        : await doctorAction({ ...context, silent: true, exitImpl: () => {} }));

    print(`1. Node >= 22.13: ${step1 ? "done" : "todo"}`);
    print(`2. Google credentials: ${step2 ? "done" : "todo"}`);
    print(`3. Account: ${step3 ? "done" : "todo"}`);
    print(`4. Extension: ${step4 ? "done" : "todo"}`);
    print(`5. Auto-start: ${step5 ? "done" : "todo"}`);
    print(`6. Doctor: ${step6 ? "done" : "todo"}`);
    return;
  }

  let prompter: SetupPrompter | undefined;

  try {
    prompter = new SetupPrompter(input, output);

    // Step 1: Check Node >= 22.13
    const nodeVer = context.nodeVersion ?? process.versions.node;
    if (!isNodeSupported(nodeVer)) {
      printError(`Node.js version ${nodeVer} is not supported. AutoOTP requires Node >= 22.13.`);
      exit(1);
      return;
    }

    // Step 2: Google credentials
    const credPath = path.join(homeDir, "credentials.json");
    const credsValid = isCredentialsValid(homeDir);

    if (!credsValid) {
      print("Google credentials setup:");
      print("  1. Create a project in Google Cloud Console (https://console.cloud.google.com).");
      print("  2. Enable the Gmail API (APIs & Services > Library > Gmail API).");
      print("  3. Set up OAuth consent screen:");
      print("     - User type: External");
      print("     - Add your Gmail address as a test user");
      print("     - Add scope: https://www.googleapis.com/auth/gmail.readonly");
      print("  4. Create Credentials > OAuth client ID > Application type: Desktop app.");
      print("  5. Download the client JSON file.");
      print("");

      const downloadsDir = context.downloadsDir ?? path.join(os.homedir(), "Downloads");
      const defaultDownloaded = findNewestDownloadedCredentials(downloadsDir);

      let chosenPath = "";
      let rawContent = "";

      while (true) {
        const promptMsg = defaultDownloaded
          ? `Path to downloaded JSON [${defaultDownloaded}]: `
          : "Path to downloaded JSON: ";
        const entered = (await prompter.ask(promptMsg)).trim();
        const candidatePath = entered || defaultDownloaded;

        if (!candidatePath) {
          printError("Please enter a path to the downloaded credentials JSON.");
          continue;
        }

        const resolved = candidatePath.startsWith("~")
          ? path.join(os.homedir(), candidatePath.slice(1).replace(/^[/\\]/, ""))
          : path.resolve(candidatePath);

        const check = validateCredentialsFile(resolved);
        if (!check.ok) {
          printError(`Invalid credentials file: ${check.error}`);
          continue;
        }

        chosenPath = resolved;
        rawContent = check.raw!;
        break;
      }

      if (fs.existsSync(credPath)) {
        const confirm = (
          await prompter.ask(`File ${credPath} already exists. Overwrite? [y/N]: `)
        )
          .trim()
          .toLowerCase();

        if (confirm !== "y" && confirm !== "yes") {
          print("Keeping existing credentials.json.");
        } else {
          fs.writeFileSync(credPath, rawContent, { mode: 0o600 });
          fs.chmodSync(credPath, 0o600);
          print(`Saved credentials to ${credPath}.`);
        }
      } else {
        fs.mkdirSync(homeDir, { recursive: true, mode: 0o700 });
        fs.writeFileSync(credPath, rawContent, { mode: 0o600 });
        fs.chmodSync(credPath, 0o600);
        print(`Saved credentials to ${credPath}.`);
      }

      const deleteConfirm = (
        await prompter.ask(`Delete downloaded original file (${chosenPath})? [y/N]: `)
      )
        .trim()
        .toLowerCase();

      if (deleteConfirm === "y" || deleteConfirm === "yes") {
        try {
          fs.unlinkSync(chosenPath);
          print(`Deleted original downloaded file.`);
        } catch (err: any) {
          printError(`Failed to delete downloaded original: ${err.message}`);
        }
      }
    }

    // Step 3: Account
    const accountsCount = await getConnectedAccountsCount(homeDir);
    if (accountsCount === 0) {
      let alias = "";
      while (true) {
        const entered = (await prompter.ask("Account alias [personal]: ")).trim();
        alias = entered || "personal";
        try {
          validateAlias(alias);
          break;
        } catch (err: any) {
          printError(err.message);
        }
      }

      if (context.loginFn) {
        await context.loginFn(alias, context);
      } else {
        await loginAction(alias, context);
      }
    }

    // Step 4: Extension
    const extId = getExtensionId(context.metaUrl ?? import.meta.url);
    const config = loadConfig(homeDir);
    const origin = `chrome-extension://${extId}`;

    if (!config.allowedOrigins.includes(origin)) {
      const extPath = resolveExtensionPath(context.metaUrl ?? import.meta.url);
      print("");
      print(`Extension folder: ${extPath}`);
      print("Instructions:");
      print("  1. Open chrome://extensions in Chrome.");
      print("  2. Turn on 'Developer mode' in the top-right corner.");
      print("  3. Click 'Load unpacked' and select the extension folder above.");
      print(`Expected Extension ID: ${extId}`);

      config.allowedOrigins.push(origin);
      saveConfig(config, homeDir);

      const pairToken = getOrCreatePairToken(homeDir);
      print("");
      print(pairToken);
      print("Paste this into the AutoOTP popup. Never share it.");
      print("");

      await prompter.ask("Press Enter once paired in browser... ");
    }

    // Step 5: Auto-start
    const platform = context.platform ?? process.platform;
    if (platform === "linux") {
      const autoStartDone = isAutoStartDone(context);
      if (!autoStartDone) {
        const ans = (await prompter.ask("Start AutoOTP automatically at login? [Y/n]: "))
          .trim()
          .toLowerCase();
        if (ans === "" || ans === "y" || ans === "yes") {
          if (context.enableFn) {
            await context.enableFn(context);
          } else {
            await enableAction(context);
          }
        } else {
          print("Skipping auto-start setup.");
        }
      }
    } else {
      print(`Auto-start is not supported on ${platform} yet.`);
    }

    // Step 6: Doctor checks & final note
    print("\nRunning health checks (doctor)...");
    if (context.doctorFn) {
      await context.doctorFn({ ...context, exitImpl: () => {} });
    } else {
      await doctorAction({ ...context, exitImpl: () => {} });
    }

    print("");
    print(
      "Note: While the Google app is in Testing mode, logins expire after about 7 days and the fix is autootp login <alias> (doctor will say when)."
    );
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg === "Setup cancelled") {
      printError("Setup cancelled");
      exit(1);
      return;
    }
    printError(msg);
    exit(1);
  } finally {
    prompter?.close();
  }
}
