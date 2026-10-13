import { Command } from "commander";
import { VERSION } from "@autootp/shared";
import {
  loginAction,
  accountsAction,
  removeAction,
  watchAction,
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

  return program;
}

