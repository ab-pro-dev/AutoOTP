#!/usr/bin/env node
import { ensureSqliteSupported } from "@autootp/shared";
import { createProgram } from "./cli.js";

try {
  ensureSqliteSupported();
} catch (err: unknown) {
  const message = err instanceof Error ? err.message : String(err);
  console.error(message);
  process.exit(1);
}

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
