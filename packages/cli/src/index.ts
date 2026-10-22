#!/usr/bin/env node
import { createProgram } from "./cli.js";

const program = createProgram();

program.exitOverride();

try {
  await program.parseAsync(process.argv);
} catch (err: unknown) {
  const code = (err as { code?: string })?.code;
  if (code === "commander.helpDisplayed" || code === "commander.version") {
    process.exit(0);
  }
  const message = err instanceof Error ? err.message : String(err);
  console.error(message.split("\n")[0]);
  const exitCode = (err as { exitCode?: number })?.exitCode ?? 1;
  process.exit(exitCode);
}
