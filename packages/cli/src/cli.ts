import { Command } from "commander";
import { VERSION } from "@autootp/shared";
import {
  loginAction,
  accountsAction,
  removeAction,
  watchAction,
  pairAction,
  serviceAction,
  enableAction,
  disableAction,
  statusAction,
  configAction,
  configSetAction,
  historyAction,
  clearAction,
  doctorAction,
  auditAction,
  extensionPathAction,
  extensionIdAction,
  setupAction,
  CommandContext
} from "./commands.js";

export function createProgram(context: CommandContext = {}): Command {
  const program = new Command();

  program
    .name("autootp")
    .description("AutoOTP - Automated OTP handling")
    .version(VERSION);

  program
    .command("login [alias]")
    .description("Connect a Gmail account via Google OAuth")
    .action(async (alias: string = "personal") => {
      await loginAction(alias, context);
    });

  program
    .command("accounts")
    .description("List all connected accounts")
    .action(async () => {
      await accountsAction(context);
    });

  program
    .command("remove <alias>")
    .description("Remove a connected account and revoke its tokens")
    .action(async (alias: string) => {
      await removeAction(alias, context);
    });

  program
    .command("watch")
    .description("Watch connected Gmail accounts for incoming OTPs")
    .action(async () => {
      await watchAction(context);
    });

  program
    .command("pair <extensionId>")
    .description("Pair a Chrome extension with AutoOTP")
    .action(async (extensionId: string) => {
      await pairAction(extensionId, context);
    });

  program
    .command("service")
    .description("Start the AutoOTP background service and WebSocket server")
    .option("--no-watch", "Start only the WebSocket server without Gmail watching")
    .action(async (opts: { watch?: boolean; noWatch?: boolean }) => {
      const noWatch = opts.watch === false || opts.noWatch === true;
      await serviceAction({ ...context, noWatch });
    });

  program
    .command("enable")
    .description("Configure and enable AutoOTP to start automatically at login")
    .action(async () => {
      await enableAction(context);
    });

  program
    .command("disable")
    .description("Disable and remove AutoOTP auto-start service")
    .action(async () => {
      await disableAction(context);
    });

  program
    .command("status")
    .description("Display the current service status and connection info")
    .action(async () => {
      await statusAction(context);
    });

  const configCmd = program
    .command("config")
    .description("Display or modify AutoOTP configuration")
    .action(async () => {
      await configAction(context);
    });

  configCmd
    .command("set <key> <value>")
    .description("Set a configuration option")
    .action(async (key: string, value: string) => {
      await configSetAction(key, value, context);
    });

  program
    .command("history")
    .description("Display recently received OTPs")
    .action(async () => {
      await historyAction(context);
    });

  program
    .command("clear")
    .description("Clear all OTP history")
    .action(async () => {
      await clearAction(context);
    });

  program
    .command("doctor")
    .description("Check AutoOTP system health and prerequisites")
    .action(async () => {
      await doctorAction(context);
    });

  program
    .command("audit")
    .description("Read-only calibration tool for analyzing OTP detection on real inbox messages")
    .option("--days <days>", "Number of days to audit (1 to 60)", "14")
    .option("--account <alias>", "Account alias to audit (default: all accounts)")
    .option("--subjects", "Include sanitized email subjects in domain groups", false)
    .option("--explain", "Print explanation details for unverified senders, false positives, and misses", false)
    .action(async (opts: { days?: string; account?: string; subjects?: boolean; explain?: boolean }) => {
      await auditAction(opts, context);
    });

  program
    .command("extension-path")
    .description("Print the absolute path to the browser extension directory")
    .action(async () => {
      await extensionPathAction(context);
    });

  program
    .command("extension-id")
    .description("Print the computed browser extension ID")
    .action(async () => {
      await extensionIdAction(context);
    });

  program
    .command("setup")
    .description("Interactive setup wizard for AutoOTP")
    .option("--dry-run", "Print status of every step as done or todo without modifying anything", false)
    .action(async (opts: { dryRun?: boolean }) => {
      await setupAction(opts, context);
    });

  return program;
}

