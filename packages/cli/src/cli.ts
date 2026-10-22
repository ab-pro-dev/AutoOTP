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

  return program;
}

